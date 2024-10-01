# cert-manager

cert-manager is a Kubernetes addon to automate the management and issuance of
TLS certificates from various issuing sources.

It will ensure certificates are valid and up to date periodically, and attempt
to renew certificates at an appropriate time before expiry.

## Prerequisites

- Kubernetes 1.22+

## Installing the Chart

Full installation instructions, including details on how to configure extra
functionality in cert-manager can be found in the [installation docs](https://cert-manager.io/docs/installation/kubernetes/).

Before installing the chart, you must first install the cert-manager CustomResourceDefinition resources.
This is performed in a separate step to allow you to easily uninstall and reinstall cert-manager without deleting your installed custom resources.

```bash
$ kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/{{RELEASE_VERSION}}/cert-manager.crds.yaml
```

To install the chart with the release name `cert-manager`:

```console
## Add the Jetstack Helm repository
$ helm repo add jetstack https://charts.jetstack.io --force-update

## Install the cert-manager helm chart
$ helm install cert-manager --namespace cert-manager --version {{RELEASE_VERSION}} jetstack/cert-manager
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

To uninstall/delete the `cert-manager` deployment:

```console
$ helm delete cert-manager --namespace cert-manager
```

The command removes all the Kubernetes components associated with the chart and deletes the release.

If you want to completely uninstall cert-manager from your cluster, you will also need to
delete the previously installed CustomResourceDefinition resources:

```console
$ kubectl delete -f https://github.com/cert-manager/cert-manager/releases/download/{{RELEASE_VERSION}}/cert-manager.crds.yaml
```

## Configuration
<!-- AUTO-GENERATED -->

### Global

#### **global.imagePullSecrets** ~ `array`
> Default value:
> ```yaml
> []
> ```

Reference to one or more secrets to be used when pulling images. For more information, see [Pull an Image from a Private Registry](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/).  
  
For example:

```yaml
imagePullSecrets:
  - name: "image-pull-secret"
```
#### **global.commonLabels** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Labels to apply to all resources.  
Please note that this does not add labels to the resources created dynamically by the controllers. For these resources, you have to add the labels in the template in the cert-manager custom resource: For example, podTemplate/ ingressTemplate in ACMEChallengeSolverHTTP01Ingress. For more information, see the [cert-manager documentation](https://cert-manager.io/docs/reference/api-docs/#acme.cert-manager.io/v1.ACMEChallengeSolverHTTP01Ingress).  
For example, secretTemplate in CertificateSpec  
For more information, see the [cert-manager documentation](https://cert-manager.io/docs/reference/api-docs/#cert-manager.io/v1.CertificateSpec).
#### **global.revisionHistoryLimit** ~ `number`

The number of old ReplicaSets to retain to allow rollback (if not set, the default Kubernetes value is set to 10).

#### **global.priorityClassName** ~ `string`
> Default value:
> ```yaml
> ""
> ```

The optional priority class to be used for the cert-manager pods.
#### **global.rbac.create** ~ `bool`
> Default value:
> ```yaml
> true
> ```

Create required ClusterRoles and ClusterRoleBindings for cert-manager.
#### **global.rbac.aggregateClusterRoles** ~ `bool`
> Default value:
> ```yaml
> true
> ```

Aggregate ClusterRoles to Kubernetes default user-facing roles. For more information, see [User-facing roles](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles)
#### **global.podSecurityPolicy.enabled** ~ `bool`
> Default value:
> ```yaml
> false
> ```

Create PodSecurityPolicy for cert-manager.  
  
Note that PodSecurityPolicy was deprecated in Kubernetes 1.21 and removed in Kubernetes 1.25.
#### **global.podSecurityPolicy.useAppArmor** ~ `bool`
> Default value:
> ```yaml
> true
> ```

Configure the PodSecurityPolicy to use AppArmor.
#### **global.logLevel** ~ `number`
> Default value:
> ```yaml
> 2
> ```

Set the verbosity of cert-manager. A range of 0 - 6, with 6 being the most verbose.
#### **global.leaderElection.namespace** ~ `string`
> Default value:
> ```yaml
> kube-system
> ```

Override the namespace used for the leader election lease.
#### **global.leaderElection.leaseDuration** ~ `string`

The duration that non-leader candidates will wait after observing a leadership renewal until attempting to acquire leadership of a led but unrenewed leader slot. This is effectively the maximum duration that a leader can be stopped before it is replaced by another candidate.

#### **global.leaderElection.renewDeadline** ~ `string`

The interval between attempts by the acting master to renew a leadership slot before it stops leading. This must be less than or equal to the lease duration.

#### **global.leaderElection.retryPeriod** ~ `string`

The duration the clients should wait between attempting acquisition and renewal of a leadership.

#### **installCRDs** ~ `bool`
> Default value:
> ```yaml
> false
> ```

This option is equivalent to setting crds.enabled=true and crds.keep=true. Deprecated: use crds.enabled and crds.keep instead.
#### **crds.enabled** ~ `bool`
> Default value:
> ```yaml
> false
> ```

This option decides if the CRDs should be installed as part of the Helm installation.
#### **crds.keep** ~ `bool`
> Default value:
> ```yaml
> true
> ```

This option makes it so that the "helm.sh/resource-policy": keep annotation is added to the CRD. This will prevent Helm from uninstalling the CRD when the Helm release is uninstalled. WARNING: when the CRDs are removed, all cert-manager custom resources  
(Certificates, Issuers, ...) will be removed too by the garbage collector.
### Controller

#### **replicaCount** ~ `number`
> Default value:
> ```yaml
> 1
> ```

The number of replicas of the cert-manager controller to run.  
  
The default is 1, but in production set this to 2 or 3 to provide high availability.  
  
If `replicas > 1`, consider setting `podDisruptionBudget.enabled=true`.  
  
Note that cert-manager uses leader election to ensure that there can only be a single instance active at a time.
#### **strategy** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Deployment update strategy for the cert-manager controller deployment. For more information, see the [Kubernetes documentation](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#strategy).  
  
For example:

```yaml
strategy:
  type: RollingUpdate
  rollingUpdate:
    maxSurge: 0
    maxUnavailable: 1
```
#### **podDisruptionBudget.enabled** ~ `bool`
> Default value:
> ```yaml
> false
> ```

Enable or disable the PodDisruptionBudget resource.  
  
This prevents downtime during voluntary disruptions such as during a Node upgrade. For example, the PodDisruptionBudget will block `kubectl drain` if it is used on the Node where the only remaining cert-manager  
Pod is currently running.
#### **podDisruptionBudget.minAvailable** ~ `number`

This configures the minimum available pods for disruptions. It can either be set to an integer (e.g. 1) or a percentage value (e.g. 25%).  
It cannot be used if `maxUnavailable` is set.

#### **podDisruptionBudget.maxUnavailable** ~ `number`

This configures the maximum unavailable pods for disruptions. It can either be set to an integer (e.g. 1) or a percentage value (e.g. 25%). it cannot be used if `minAvailable` is set.

#### **featureGates** ~ `string`
> Default value:
> ```yaml
> ""
> ```

A comma-separated list of feature gates that should be enabled on the controller pod.
#### **maxConcurrentChallenges** ~ `number`
> Default value:
> ```yaml
> 60
> ```

The maximum number of challenges that can be scheduled as 'processing' at once.
#### **image.registry** ~ `string`

The container registry to pull the manager image from.

#### **image.repository** ~ `string`
> Default value:
> ```yaml
> quay.io/jetstack/cert-manager-controller
> ```

The container image for the cert-manager controller.

#### **image.tag** ~ `string`

Override the image tag to deploy by setting this variable. If no value is set, the chart's appVersion is used.

#### **image.digest** ~ `string`

Setting a digest will override any tag.

#### **image.pullPolicy** ~ `string`
> Default value:
> ```yaml
> IfNotPresent
> ```

Kubernetes imagePullPolicy on Deployment.
#### **clusterResourceNamespace** ~ `string`
> Default value:
> ```yaml
> ""
> ```

Override the namespace used to store DNS provider credentials etc. for ClusterIssuer resources. By default, the same namespace as cert-manager is deployed within is used. This namespace will not be automatically created by the Helm chart.
#### **namespace** ~ `string`
> Default value:
> ```yaml
> ""
> ```

This namespace allows you to define where the services are installed into. If not set then they use the namespace of the release. This is helpful when installing cert manager as a chart dependency (sub chart).
#### **fullnameOverride** ~ `string`

Override the "cert-manager.fullname" value. This value is used as part of most of the names of the resources created by this Helm chart.

#### **nameOverride** ~ `string`

Override the "cert-manager.name" value, which is used to annotate some of the resources that are created by this Chart (using "app.kubernetes.io/name"). NOTE: There are some inconsistencies in the Helm chart when it comes to these annotations (some resources use eg. "cainjector.name" which resolves to the value "cainjector").

#### **serviceAccount.create** ~ `bool`
> Default value:
> ```yaml
> true
> ```

Specifies whether a service account should be created.
#### **serviceAccount.name** ~ `string`

The name of the service account to use.  
If not set and create is true, a name is generated using the fullname template.

#### **serviceAccount.annotations** ~ `object`

Optional additional annotations to add to the controller's Service Account.

#### **serviceAccount.labels** ~ `object`

Optional additional labels to add to the controller's Service Account.

#### **serviceAccount.automountServiceAccountToken** ~ `bool`
> Default value:
> ```yaml
> true
> ```

Automount API credentials for a Service Account.
#### **automountServiceAccountToken** ~ `bool`

Automounting API credentials for a particular pod.

#### **enableCertificateOwnerRef** ~ `bool`
> Default value:
> ```yaml
> false
> ```

When this flag is enabled, secrets will be automatically removed when the certificate resource is deleted.
#### **config** ~ `object`
> Default value:
> ```yaml
> {}
> ```

This property is used to configure options for the controller pod. This allows setting options that would usually be provided using flags.  
  
If `apiVersion` and `kind` are unspecified they default to the current latest version (currently `controller.config.cert-manager.io/v1alpha1`). You can pin the version by specifying the `apiVersion` yourself.  
  
For example:

```yaml
config:
  apiVersion: controller.config.cert-manager.io/v1alpha1
  kind: ControllerConfiguration
  logging:
    verbosity: 2
    format: text
  leaderElectionConfig:
    namespace: kube-system
  kubernetesAPIQPS: 9000
  kubernetesAPIBurst: 9000
  numberOfConcurrentWorkers: 200
  featureGates:
    AdditionalCertificateOutputFormats: true
    DisallowInsecureCSRUsageDefinition: true
    ExperimentalCertificateSigningRequestControllers: true
    ExperimentalGatewayAPISupport: true
    LiteralCertificateSubject: true
    SecretsFilteredCaching: true
    ServerSideApply: true
    StableCertificateRequestName: true
    UseCertificateRequestBasicConstraints: true
    ValidateCAA: true
  # Configure the metrics server for TLS
  # See https://cert-manager.io/docs/devops-tips/prometheus-metrics/#tls
  metricsTLSConfig:
    dynamic:
      secretNamespace: "cert-manager"
      secretName: "cert-manager-metrics-ca"
      dnsNames:
      - cert-manager-metrics
```
#### **dns01RecursiveNameservers** ~ `string`
> Default value:
> ```yaml
> ""
> ```

A comma-separated string with the host and port of the recursive nameservers cert-manager should query.
#### **dns01RecursiveNameserversOnly** ~ `bool`
> Default value:
> ```yaml
> false
> ```

Forces cert-manager to use only the recursive nameservers for verification. Enabling this option could cause the DNS01 self check to take longer owing to caching performed by the recursive nameservers.
#### **disableAutoApproval** ~ `bool`
> Default value:
> ```yaml
> false
> ```

Option to disable cert-manager's build-in auto-approver. The auto-approver approves all CertificateRequests that reference issuers matching the 'approveSignerNames' option. This 'disableAutoApproval' option is useful when you want to make all approval decisions using a different approver (like approver-policy - https://github.com/cert-manager/approver-policy).
#### **approveSignerNames** ~ `array`
> Default value:
> ```yaml
> - issuers.cert-manager.io/*
> - clusterissuers.cert-manager.io/*
> ```

List of signer names that cert-manager will approve by default. CertificateRequests referencing these signer names will be auto-approved by cert-manager. Defaults to just approving the cert-manager.io Issuer and ClusterIssuer issuers. When set to an empty array, ALL issuers will be auto-approved by cert-manager. To disable the auto-approval, because eg. you are using approver-policy, you can enable 'disableAutoApproval'.  
ref: https://cert-manager.io/docs/concepts/certificaterequest/#approval

#### **extraArgs** ~ `array`
> Default value:
> ```yaml
> []
> ```

Additional command line flags to pass to cert-manager controller binary. To see all available flags run `docker run quay.io/jetstack/cert-manager-controller:<version> --help`.  
  
Use this flag to enable or disable arbitrary controllers. For example, to disable the CertificateRequests approver.  
  
For example:

```yaml
extraArgs:
  - --controllers=*,-certificaterequests-approver
```
#### **extraEnv** ~ `array`
> Default value:
> ```yaml
> []
> ```

Additional environment variables to pass to cert-manager controller binary.  
For example:

```yaml
extraEnv:
- name: SOME_VAR
  value: 'some value'
```
#### **resources** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Resources to provide to the cert-manager controller pod.  
  
For example:

```yaml
requests:
  cpu: 10m
  memory: 32Mi
```

For more information, see [Resource Management for Pods and Containers](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/).
#### **securityContext** ~ `object`
> Default value:
> ```yaml
> runAsNonRoot: true
> seccompProfile:
>   type: RuntimeDefault
> ```

Pod Security Context.  
For more information, see [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).

#### **containerSecurityContext** ~ `object`
> Default value:
> ```yaml
> allowPrivilegeEscalation: false
> capabilities:
>   drop:
>     - ALL
> readOnlyRootFilesystem: true
> ```

Container Security Context to be set on the controller component container. For more information, see [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).

#### **volumes** ~ `array`
> Default value:
> ```yaml
> []
> ```

Additional volumes to add to the cert-manager controller pod.
#### **volumeMounts** ~ `array`
> Default value:
> ```yaml
> []
> ```

Additional volume mounts to add to the cert-manager controller container.
#### **deploymentAnnotations** ~ `object`

Optional additional annotations to add to the controller Deployment.

#### **podAnnotations** ~ `object`

Optional additional annotations to add to the controller Pods.

#### **podLabels** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Optional additional labels to add to the controller Pods.
#### **serviceAnnotations** ~ `object`

Optional annotations to add to the controller Service.

#### **serviceLabels** ~ `object`

Optional additional labels to add to the controller Service.

#### **serviceIPFamilyPolicy** ~ `string`

Optionally set the IP family policy for the controller Service to configure dual-stack; see [Configure dual-stack](https://kubernetes.io/docs/concepts/services-networking/dual-stack/#services).

#### **serviceIPFamilies** ~ `array`

Optionally set the IP families for the controller Service that should be supported, in the order in which they should be applied to ClusterIP. Can be IPv4 and/or IPv6.

#### **podDnsPolicy** ~ `string`

Pod DNS policy.  
For more information, see [Pod's DNS Policy](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-s-dns-policy).

#### **podDnsConfig** ~ `object`

Pod DNS configuration. The podDnsConfig field is optional and can work with any podDnsPolicy settings. However, when a Pod's dnsPolicy is set to "None", the dnsConfig field has to be specified. For more information, see [Pod's DNS Config](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-dns-config).

#### **hostAliases** ~ `array`
> Default value:
> ```yaml
> []
> ```

Optional hostAliases for cert-manager-controller pods. May be useful when performing ACME DNS-01 self checks.
#### **nodeSelector** ~ `object`
> Default value:
> ```yaml
> kubernetes.io/os: linux
> ```

The nodeSelector on Pods tells Kubernetes to schedule Pods on the nodes with matching labels. For more information, see [Assigning Pods to Nodes](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/).  
  
This default ensures that Pods are only scheduled to Linux nodes. It prevents Pods being scheduled to Windows nodes in a mixed OS cluster.

#### **ingressShim.defaultIssuerName** ~ `string`

Optional default issuer to use for ingress resources.

#### **ingressShim.defaultIssuerKind** ~ `string`

Optional default issuer kind to use for ingress resources.

#### **ingressShim.defaultIssuerGroup** ~ `string`

Optional default issuer group to use for ingress resources.

#### **http_proxy** ~ `string`

Configures the HTTP_PROXY environment variable where a HTTP proxy is required.

#### **https_proxy** ~ `string`

Configures the HTTPS_PROXY environment variable where a HTTP proxy is required.

#### **no_proxy** ~ `string`

Configures the NO_PROXY environment variable where a HTTP proxy is required, but certain domains should be excluded.

#### **affinity** ~ `object`
> Default value:
> ```yaml
> {}
> ```

A Kubernetes Affinity, if required. For more information, see [Affinity v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#affinity-v1-core).  
  
For example:

```yaml
affinity:
  nodeAffinity:
   requiredDuringSchedulingIgnoredDuringExecution:
     nodeSelectorTerms:
     - matchExpressions:
       - key: foo.bar.com/role
         operator: In
         values:
         - master
```
#### **tolerations** ~ `array`
> Default value:
> ```yaml
> []
> ```

A list of Kubernetes Tolerations, if required. For more information, see [Toleration v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#toleration-v1-core).  
  
For example:

```yaml
tolerations:
- key: foo.bar.com/role
  operator: Equal
  value: master
  effect: NoSchedule
```
#### **topologySpreadConstraints** ~ `array`
> Default value:
> ```yaml
> []
> ```

A list of Kubernetes TopologySpreadConstraints, if required. For more information, see [Topology spread constraint v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#topologyspreadconstraint-v1-core  
  
For example:

```yaml
topologySpreadConstraints:
- maxSkew: 2
  topologyKey: topology.kubernetes.io/zone
  whenUnsatisfiable: ScheduleAnyway
  labelSelector:
    matchLabels:
      app.kubernetes.io/instance: cert-manager
      app.kubernetes.io/component: controller
```
#### **livenessProbe** ~ `object`
> Default value:
> ```yaml
> enabled: true
> failureThreshold: 8
> initialDelaySeconds: 10
> periodSeconds: 10
> successThreshold: 1
> timeoutSeconds: 15
> ```

LivenessProbe settings for the controller container of the controller Pod.  
  
This is enabled by default, in order to enable the clock-skew liveness probe that restarts the controller in case of a skew between the system clock and the monotonic clock. LivenessProbe durations and thresholds are based on those used for the Kubernetes controller-manager. For more information see the following on the  
[Kubernetes GitHub repository](https://github.com/kubernetes/kubernetes/blob/806b30170c61a38fedd54cc9ede4cd6275a1ad3b/cmd/kubeadm/app/util/staticpod/utils.go#L241-L245)

#### **enableServiceLinks** ~ `bool`
> Default value:
> ```yaml
> false
> ```

enableServiceLinks indicates whether information about services should be injected into the pod's environment variables, matching the syntax of Docker links.
### Prometheus

#### **prometheus.enabled** ~ `bool`
> Default value:
> ```yaml
> true
> ```

Enable Prometheus monitoring for the cert-manager controller and webhook. If you use the Prometheus Operator, set prometheus.podmonitor.enabled or prometheus.servicemonitor.enabled, to create a PodMonitor or a  
ServiceMonitor resource.  
Otherwise, 'prometheus.io' annotations are added to the cert-manager and cert-manager-webhook Deployments. Note that you can not enable both PodMonitor and ServiceMonitor as they are mutually exclusive. Enabling both will result in an error.
#### **prometheus.servicemonitor.enabled** ~ `bool`
> Default value:
> ```yaml
> false
> ```

Create a ServiceMonitor to add cert-manager to Prometheus.
#### **prometheus.servicemonitor.namespace** ~ `string`

The namespace that the service monitor should live in, defaults to the cert-manager namespace.

#### **prometheus.servicemonitor.prometheusInstance** ~ `string`
> Default value:
> ```yaml
> default
> ```

Specifies the `prometheus` label on the created ServiceMonitor. This is used when different Prometheus instances have label selectors matching different ServiceMonitors.
#### **prometheus.servicemonitor.targetPort** ~ `number`
> Default value:
> ```yaml
> 9402
> ```

The target port to set on the ServiceMonitor. This must match the port that the cert-manager controller is listening on for metrics.
#### **prometheus.servicemonitor.path** ~ `string`
> Default value:
> ```yaml
> /metrics
> ```

The path to scrape for metrics.
#### **prometheus.servicemonitor.interval** ~ `string`
> Default value:
> ```yaml
> 60s
> ```

The interval to scrape metrics.
#### **prometheus.servicemonitor.scrapeTimeout** ~ `string`
> Default value:
> ```yaml
> 30s
> ```

The timeout before a metrics scrape fails.
#### **prometheus.servicemonitor.labels** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Additional labels to add to the ServiceMonitor.
#### **prometheus.servicemonitor.annotations** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Additional annotations to add to the ServiceMonitor.
#### **prometheus.servicemonitor.honorLabels** ~ `bool`
> Default value:
> ```yaml
> false
> ```

Keep labels from scraped data, overriding server-side labels.
#### **prometheus.servicemonitor.endpointAdditionalProperties** ~ `object`
> Default value:
> ```yaml
> {}
> ```

EndpointAdditionalProperties allows setting additional properties on the endpoint such as relabelings, metricRelabelings etc.  
  
For example:

```yaml
endpointAdditionalProperties:
 relabelings:
 - action: replace
   sourceLabels:
   - __meta_kubernetes_pod_node_name
   targetLabel: instance
```



#### **prometheus.podmonitor.enabled** ~ `bool`
> Default value:
> ```yaml
> false
> ```

Create a PodMonitor to add cert-manager to Prometheus.
#### **prometheus.podmonitor.namespace** ~ `string`

The namespace that the pod monitor should live in, defaults to the cert-manager namespace.

#### **prometheus.podmonitor.prometheusInstance** ~ `string`
> Default value:
> ```yaml
> default
> ```

Specifies the `prometheus` label on the created PodMonitor. This is used when different Prometheus instances have label selectors matching different PodMonitors.
#### **prometheus.podmonitor.path** ~ `string`
> Default value:
> ```yaml
> /metrics
> ```

The path to scrape for metrics.
#### **prometheus.podmonitor.interval** ~ `string`
> Default value:
> ```yaml
> 60s
> ```

The interval to scrape metrics.
#### **prometheus.podmonitor.scrapeTimeout** ~ `string`
> Default value:
> ```yaml
> 30s
> ```

The timeout before a metrics scrape fails.
#### **prometheus.podmonitor.labels** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Additional labels to add to the PodMonitor.
#### **prometheus.podmonitor.annotations** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Additional annotations to add to the PodMonitor.
#### **prometheus.podmonitor.honorLabels** ~ `bool`
> Default value:
> ```yaml
> false
> ```

Keep labels from scraped data, overriding server-side labels.
#### **prometheus.podmonitor.endpointAdditionalProperties** ~ `object`
> Default value:
> ```yaml
> {}
> ```

EndpointAdditionalProperties allows setting additional properties on the endpoint such as relabelings, metricRelabelings etc.  
  
For example:

```yaml
endpointAdditionalProperties:
 relabelings:
 - action: replace
   sourceLabels:
   - __meta_kubernetes_pod_node_name
   targetLabel: instance
 # Configure the PodMonitor for TLS connections
 # See https://cert-manager.io/docs/devops-tips/prometheus-metrics/#tls
 scheme: https
 tlsConfig:
   serverName: cert-manager-metrics
   ca:
     secret:
       name: cert-manager-metrics-ca
       key: "tls.crt"
```



### Webhook

#### **webhook.replicaCount** ~ `number`
> Default value:
> ```yaml
> 1
> ```

Number of replicas of the cert-manager webhook to run.  
  
The default is 1, but in production set this to 2 or 3 to provide high availability.  
  
If `replicas > 1`, consider setting `webhook.podDisruptionBudget.enabled=true`.
#### **webhook.timeoutSeconds** ~ `number`
> Default value:
> ```yaml
> 30
> ```

The number of seconds the API server should wait for the webhook to respond before treating the call as a failure. The value must be between 1 and 30 seconds. For more information, see  
[Validating webhook configuration v1](https://kubernetes.io/docs/reference/kubernetes-api/extend-resources/validating-webhook-configuration-v1/).  
  
The default is set to the maximum value of 30 seconds as users sometimes report that the connection between the K8S API server and the cert-manager webhook server times out. If *this* timeout is reached, the error message will be "context deadline exceeded", which doesn't help the user diagnose what phase of the HTTPS connection timed out. For example, it could be during DNS resolution, TCP connection, TLS negotiation, HTTP negotiation, or slow HTTP response from the webhook server. By setting this timeout to its maximum value the underlying timeout error message has more chance of being returned to the end user.
#### **webhook.config** ~ `object`
> Default value:
> ```yaml
> {}
> ```

This is used to configure options for the webhook pod. This allows setting options that would usually be provided using flags.  
  
If `apiVersion` and `kind` are unspecified they default to the current latest version (currently `webhook.config.cert-manager.io/v1alpha1`). You can pin the version by specifying the `apiVersion` yourself.  
  
For example:

```yaml
apiVersion: webhook.config.cert-manager.io/v1alpha1
kind: WebhookConfiguration
# The port that the webhook listens on for requests.
# In GKE private clusters, by default Kubernetes apiservers are allowed to
# talk to the cluster nodes only on 443 and 10250. Configuring
# securePort: 10250 therefore will work out-of-the-box without needing to add firewall
# rules or requiring NET_BIND_SERVICE capabilities to bind port numbers < 1000.
# This should be uncommented and set as a default by the chart once
# the apiVersion of WebhookConfiguration graduates beyond v1alpha1.
securePort: 10250
# Configure the metrics server for TLS
# See https://cert-manager.io/docs/devops-tips/prometheus-metrics/#tls
metricsTLSConfig:
  dynamic:
    secretNamespace: "cert-manager"
    secretName: "cert-manager-metrics-ca"
    dnsNames:
    - cert-manager-metrics
```
#### **webhook.strategy** ~ `object`
> Default value:
> ```yaml
> {}
> ```

The update strategy for the cert-manager webhook deployment. For more information, see the [Kubernetes documentation](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#strategy)  
  
For example:

```yaml
strategy:
  type: RollingUpdate
  rollingUpdate:
    maxSurge: 0
    maxUnavailable: 1
```
#### **webhook.securityContext** ~ `object`
> Default value:
> ```yaml
> runAsNonRoot: true
> seccompProfile:
>   type: RuntimeDefault
> ```

Pod Security Context to be set on the webhook component Pod. For more information, see [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).

#### **webhook.containerSecurityContext** ~ `object`
> Default value:
> ```yaml
> allowPrivilegeEscalation: false
> capabilities:
>   drop:
>     - ALL
> readOnlyRootFilesystem: true
> ```

Container Security Context to be set on the webhook component container. For more information, see [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).

#### **webhook.podDisruptionBudget.enabled** ~ `bool`
> Default value:
> ```yaml
> false
> ```

Enable or disable the PodDisruptionBudget resource.  
  
This prevents downtime during voluntary disruptions such as during a Node upgrade. For example, the PodDisruptionBudget will block `kubectl drain` if it is used on the Node where the only remaining cert-manager  
Pod is currently running.
#### **webhook.podDisruptionBudget.minAvailable** ~ `number`

This property configures the minimum available pods for disruptions. Can either be set to an integer (e.g. 1) or a percentage value (e.g. 25%).  
It cannot be used if `maxUnavailable` is set.

#### **webhook.podDisruptionBudget.maxUnavailable** ~ `number`

This property configures the maximum unavailable pods for disruptions. Can either be set to an integer (e.g. 1) or a percentage value (e.g. 25%).  
It cannot be used if `minAvailable` is set.

#### **webhook.deploymentAnnotations** ~ `object`

Optional additional annotations to add to the webhook Deployment.

#### **webhook.podAnnotations** ~ `object`

Optional additional annotations to add to the webhook Pods.

#### **webhook.serviceAnnotations** ~ `object`

Optional additional annotations to add to the webhook Service.

#### **webhook.mutatingWebhookConfigurationAnnotations** ~ `object`

Optional additional annotations to add to the webhook MutatingWebhookConfiguration.

#### **webhook.validatingWebhookConfigurationAnnotations** ~ `object`

Optional additional annotations to add to the webhook ValidatingWebhookConfiguration.

#### **webhook.validatingWebhookConfiguration.namespaceSelector** ~ `object`
> Default value:
> ```yaml
> matchExpressions:
>   - key: cert-manager.io/disable-validation
>     operator: NotIn
>     values:
>       - "true"
> ```

Configure spec.namespaceSelector for validating webhooks.

#### **webhook.mutatingWebhookConfiguration.namespaceSelector** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Configure spec.namespaceSelector for mutating webhooks.

#### **webhook.extraArgs** ~ `array`
> Default value:
> ```yaml
> []
> ```

Additional command line flags to pass to cert-manager webhook binary. To see all available flags run `docker run quay.io/jetstack/cert-manager-webhook:<version> --help`.
#### **webhook.extraEnv** ~ `array`
> Default value:
> ```yaml
> []
> ```

Additional environment variables to pass to cert-manager webhook binary.  
For example:

```yaml
extraEnv:
- name: SOME_VAR
  value: 'some value'
```
#### **webhook.featureGates** ~ `string`
> Default value:
> ```yaml
> ""
> ```

Comma separated list of feature gates that should be enabled on the webhook pod.
#### **webhook.resources** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Resources to provide to the cert-manager webhook pod.  
  
For example:

```yaml
requests:
  cpu: 10m
  memory: 32Mi
```

For more information, see [Resource Management for Pods and Containers](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/).
#### **webhook.livenessProbe** ~ `object`
> Default value:
> ```yaml
> failureThreshold: 3
> initialDelaySeconds: 60
> periodSeconds: 10
> successThreshold: 1
> timeoutSeconds: 1
> ```

Liveness probe values.  
For more information, see [Container probes](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#container-probes).

#### **webhook.readinessProbe** ~ `object`
> Default value:
> ```yaml
> failureThreshold: 3
> initialDelaySeconds: 5
> periodSeconds: 5
> successThreshold: 1
> timeoutSeconds: 1
> ```

Readiness probe values.  
For more information, see [Container probes](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#container-probes).

#### **webhook.nodeSelector** ~ `object`
> Default value:
> ```yaml
> kubernetes.io/os: linux
> ```

The nodeSelector on Pods tells Kubernetes to schedule Pods on the nodes with matching labels. For more information, see [Assigning Pods to Nodes](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/).  
  
This default ensures that Pods are only scheduled to Linux nodes. It prevents Pods being scheduled to Windows nodes in a mixed OS cluster.

#### **webhook.affinity** ~ `object`
> Default value:
> ```yaml
> {}
> ```

A Kubernetes Affinity, if required. For more information, see [Affinity v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#affinity-v1-core).  
  
For example:

```yaml
affinity:
  nodeAffinity:
   requiredDuringSchedulingIgnoredDuringExecution:
     nodeSelectorTerms:
     - matchExpressions:
       - key: foo.bar.com/role
         operator: In
         values:
         - master
```
#### **webhook.tolerations** ~ `array`
> Default value:
> ```yaml
> []
> ```

A list of Kubernetes Tolerations, if required. For more information, see [Toleration v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#toleration-v1-core).  
  
For example:

```yaml
tolerations:
- key: foo.bar.com/role
  operator: Equal
  value: master
  effect: NoSchedule
```
#### **webhook.topologySpreadConstraints** ~ `array`
> Default value:
> ```yaml
> []
> ```

A list of Kubernetes TopologySpreadConstraints, if required. For more information, see [Topology spread constraint v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#topologyspreadconstraint-v1-core).  
  
For example:

```yaml
topologySpreadConstraints:
- maxSkew: 2
  topologyKey: topology.kubernetes.io/zone
  whenUnsatisfiable: ScheduleAnyway
  labelSelector:
    matchLabels:
      app.kubernetes.io/instance: cert-manager
      app.kubernetes.io/component: controller
```
#### **webhook.podLabels** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Optional additional labels to add to the Webhook Pods.
#### **webhook.serviceLabels** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Optional additional labels to add to the Webhook Service.
#### **webhook.serviceIPFamilyPolicy** ~ `string`
> Default value:
> ```yaml
> ""
> ```

Optionally set the IP family policy for the controller Service to configure dual-stack; see [Configure dual-stack](https://kubernetes.io/docs/concepts/services-networking/dual-stack/#services).
#### **webhook.serviceIPFamilies** ~ `array`
> Default value:
> ```yaml
> []
> ```

Optionally set the IP families for the controller Service that should be supported, in the order in which they should be applied to ClusterIP. Can be IPv4 and/or IPv6.
#### **webhook.image.registry** ~ `string`

The container registry to pull the webhook image from.

#### **webhook.image.repository** ~ `string`
> Default value:
> ```yaml
> quay.io/jetstack/cert-manager-webhook
> ```

The container image for the cert-manager webhook

#### **webhook.image.tag** ~ `string`

Override the image tag to deploy by setting this variable. If no value is set, the chart's appVersion will be used.

#### **webhook.image.digest** ~ `string`

Setting a digest will override any tag

#### **webhook.image.pullPolicy** ~ `string`
> Default value:
> ```yaml
> IfNotPresent
> ```

Kubernetes imagePullPolicy on Deployment.
#### **webhook.serviceAccount.create** ~ `bool`
> Default value:
> ```yaml
> true
> ```

Specifies whether a service account should be created.
#### **webhook.serviceAccount.name** ~ `string`

The name of the service account to use.  
If not set and create is true, a name is generated using the fullname template.

#### **webhook.serviceAccount.annotations** ~ `object`

Optional additional annotations to add to the controller's Service Account.

#### **webhook.serviceAccount.labels** ~ `object`

Optional additional labels to add to the webhook's Service Account.

#### **webhook.serviceAccount.automountServiceAccountToken** ~ `bool`
> Default value:
> ```yaml
> true
> ```

Automount API credentials for a Service Account.
#### **webhook.automountServiceAccountToken** ~ `bool`

Automounting API credentials for a particular pod.

#### **webhook.securePort** ~ `number`
> Default value:
> ```yaml
> 10250
> ```

The port that the webhook listens on for requests. In GKE private clusters, by default Kubernetes apiservers are allowed to talk to the cluster nodes only on 443 and 10250. Configuring securePort: 10250, therefore will work out-of-the-box without needing to add firewall rules or requiring NET_BIND_SERVICE capabilities to bind port numbers <1000.
#### **webhook.hostNetwork** ~ `bool`
> Default value:
> ```yaml
> false
> ```

Specifies if the webhook should be started in hostNetwork mode.  
  
Required for use in some managed kubernetes clusters (such as AWS EKS) with custom. CNI (such as calico), because control-plane managed by AWS cannot communicate with pods' IP CIDR and admission webhooks are not working  
  
Since the default port for the webhook conflicts with kubelet on the host network, `webhook.securePort` should be changed to an available port if running in hostNetwork mode.
#### **webhook.serviceType** ~ `string`
> Default value:
> ```yaml
> ClusterIP
> ```

Specifies how the service should be handled. Useful if you want to expose the webhook outside of the cluster. In some cases, the control plane cannot reach internal services.
#### **webhook.loadBalancerIP** ~ `string`

Specify the load balancer IP for the created service.

#### **webhook.url** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Overrides the mutating webhook and validating webhook so they reach the webhook service using the `url` field instead of a service.
#### **webhook.networkPolicy.enabled** ~ `bool`
> Default value:
> ```yaml
> false
> ```

Create network policies for the webhooks.
#### **webhook.networkPolicy.ingress** ~ `array`
> Default value:
> ```yaml
> - from:
>     - ipBlock:
>         cidr: 0.0.0.0/0
> ```

Ingress rule for the webhook network policy. By default, it allows all inbound traffic.

#### **webhook.networkPolicy.egress** ~ `array`
> Default value:
> ```yaml
> - ports:
>     - port: 80
>       protocol: TCP
>     - port: 443
>       protocol: TCP
>     - port: 53
>       protocol: TCP
>     - port: 53
>       protocol: UDP
>     - port: 6443
>       protocol: TCP
>   to:
>     - ipBlock:
>         cidr: 0.0.0.0/0
> ```

Egress rule for the webhook network policy. By default, it allows all outbound traffic to ports 80 and 443, as well as DNS ports.

#### **webhook.volumes** ~ `array`
> Default value:
> ```yaml
> []
> ```

Additional volumes to add to the cert-manager controller pod.
#### **webhook.volumeMounts** ~ `array`
> Default value:
> ```yaml
> []
> ```

Additional volume mounts to add to the cert-manager controller container.
#### **webhook.enableServiceLinks** ~ `bool`
> Default value:
> ```yaml
> false
> ```

enableServiceLinks indicates whether information about services should be injected into the pod's environment variables, matching the syntax of Docker links.
### CA Injector

#### **cainjector.enabled** ~ `bool`
> Default value:
> ```yaml
> true
> ```

Create the CA Injector deployment
#### **cainjector.replicaCount** ~ `number`
> Default value:
> ```yaml
> 1
> ```

The number of replicas of the cert-manager cainjector to run.  
  
The default is 1, but in production set this to 2 or 3 to provide high availability.  
  
If `replicas > 1`, consider setting `cainjector.podDisruptionBudget.enabled=true`.  
  
Note that cert-manager uses leader election to ensure that there can only be a single instance active at a time.
#### **cainjector.config** ~ `object`
> Default value:
> ```yaml
> {}
> ```

This is used to configure options for the cainjector pod. It allows setting options that are usually provided via flags.  
  
If `apiVersion` and `kind` are unspecified they default to the current latest version (currently `cainjector.config.cert-manager.io/v1alpha1`). You can pin the version by specifying the `apiVersion` yourself.  
  
For example:

```yaml
apiVersion: cainjector.config.cert-manager.io/v1alpha1
kind: CAInjectorConfiguration
logging:
 verbosity: 2
 format: text
leaderElectionConfig:
 namespace: kube-system
# Configure the metrics server for TLS
# See https://cert-manager.io/docs/devops-tips/prometheus-metrics/#tls
metricsTLSConfig:
  dynamic:
    secretNamespace: "cert-manager"
    secretName: "cert-manager-metrics-ca"
    dnsNames:
    - cert-manager-metrics
```
#### **cainjector.strategy** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Deployment update strategy for the cert-manager cainjector deployment. For more information, see the [Kubernetes documentation](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#strategy).  
  
For example:

```yaml
strategy:
  type: RollingUpdate
  rollingUpdate:
    maxSurge: 0
    maxUnavailable: 1
```
#### **cainjector.securityContext** ~ `object`
> Default value:
> ```yaml
> runAsNonRoot: true
> seccompProfile:
>   type: RuntimeDefault
> ```

Pod Security Context to be set on the cainjector component Pod. For more information, see [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).

#### **cainjector.containerSecurityContext** ~ `object`
> Default value:
> ```yaml
> allowPrivilegeEscalation: false
> capabilities:
>   drop:
>     - ALL
> readOnlyRootFilesystem: true
> ```

Container Security Context to be set on the cainjector component container. For more information, see [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).

#### **cainjector.podDisruptionBudget.enabled** ~ `bool`
> Default value:
> ```yaml
> false
> ```

Enable or disable the PodDisruptionBudget resource.  
  
This prevents downtime during voluntary disruptions such as during a Node upgrade. For example, the PodDisruptionBudget will block `kubectl drain` if it is used on the Node where the only remaining cert-manager  
Pod is currently running.
#### **cainjector.podDisruptionBudget.minAvailable** ~ `number`

`minAvailable` configures the minimum available pods for disruptions. It can either be set to  
an integer (e.g. 1) or a percentage value (e.g. 25%).  
Cannot be used if `maxUnavailable` is set.

#### **cainjector.podDisruptionBudget.maxUnavailable** ~ `number`

`maxUnavailable` configures the maximum unavailable pods for disruptions. It can either be set to  
an integer (e.g. 1) or a percentage value (e.g. 25%).  
Cannot be used if `minAvailable` is set.

#### **cainjector.deploymentAnnotations** ~ `object`

Optional additional annotations to add to the cainjector Deployment.

#### **cainjector.podAnnotations** ~ `object`

Optional additional annotations to add to the cainjector Pods.

#### **cainjector.serviceAnnotations** ~ `object`

Optional additional annotations to add to the cainjector metrics Service.

#### **cainjector.extraArgs** ~ `array`
> Default value:
> ```yaml
> []
> ```

Additional command line flags to pass to cert-manager cainjector binary. To see all available flags run `docker run quay.io/jetstack/cert-manager-cainjector:<version> --help`.
#### **cainjector.extraEnv** ~ `array`
> Default value:
> ```yaml
> []
> ```

Additional environment variables to pass to cert-manager cainjector binary.  
For example:

```yaml
extraEnv:
- name: SOME_VAR
  value: 'some value'
```
#### **cainjector.featureGates** ~ `string`
> Default value:
> ```yaml
> ""
> ```

Comma separated list of feature gates that should be enabled on the cainjector pod.
#### **cainjector.resources** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Resources to provide to the cert-manager cainjector pod.  
  
For example:

```yaml
requests:
  cpu: 10m
  memory: 32Mi
```

For more information, see [Resource Management for Pods and Containers](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/).
#### **cainjector.nodeSelector** ~ `object`
> Default value:
> ```yaml
> kubernetes.io/os: linux
> ```

The nodeSelector on Pods tells Kubernetes to schedule Pods on the nodes with matching labels. For more information, see [Assigning Pods to Nodes](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/).  
  
This default ensures that Pods are only scheduled to Linux nodes. It prevents Pods being scheduled to Windows nodes in a mixed OS cluster.

#### **cainjector.affinity** ~ `object`
> Default value:
> ```yaml
> {}
> ```

A Kubernetes Affinity, if required. For more information, see [Affinity v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#affinity-v1-core).  
  
For example:

```yaml
affinity:
  nodeAffinity:
   requiredDuringSchedulingIgnoredDuringExecution:
     nodeSelectorTerms:
     - matchExpressions:
       - key: foo.bar.com/role
         operator: In
         values:
         - master
```
#### **cainjector.tolerations** ~ `array`
> Default value:
> ```yaml
> []
> ```

A list of Kubernetes Tolerations, if required. For more information, see [Toleration v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#toleration-v1-core).  
  
For example:

```yaml
tolerations:
- key: foo.bar.com/role
  operator: Equal
  value: master
  effect: NoSchedule
```
#### **cainjector.topologySpreadConstraints** ~ `array`
> Default value:
> ```yaml
> []
> ```

A list of Kubernetes TopologySpreadConstraints, if required. For more information, see [Topology spread constraint v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#topologyspreadconstraint-v1-core).  
  
For example:

```yaml
topologySpreadConstraints:
- maxSkew: 2
  topologyKey: topology.kubernetes.io/zone
  whenUnsatisfiable: ScheduleAnyway
  labelSelector:
    matchLabels:
      app.kubernetes.io/instance: cert-manager
      app.kubernetes.io/component: controller
```
#### **cainjector.podLabels** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Optional additional labels to add to the CA Injector Pods.
#### **cainjector.serviceLabels** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Optional additional labels to add to the CA Injector metrics Service.
#### **cainjector.image.registry** ~ `string`

The container registry to pull the cainjector image from.

#### **cainjector.image.repository** ~ `string`
> Default value:
> ```yaml
> quay.io/jetstack/cert-manager-cainjector
> ```

The container image for the cert-manager cainjector

#### **cainjector.image.tag** ~ `string`

Override the image tag to deploy by setting this variable. If no value is set, the chart's appVersion will be used.

#### **cainjector.image.digest** ~ `string`

Setting a digest will override any tag.

#### **cainjector.image.pullPolicy** ~ `string`
> Default value:
> ```yaml
> IfNotPresent
> ```

Kubernetes imagePullPolicy on Deployment.
#### **cainjector.serviceAccount.create** ~ `bool`
> Default value:
> ```yaml
> true
> ```

Specifies whether a service account should be created.
#### **cainjector.serviceAccount.name** ~ `string`

The name of the service account to use.  
If not set and create is true, a name is generated using the fullname template

#### **cainjector.serviceAccount.annotations** ~ `object`

Optional additional annotations to add to the controller's Service Account.

#### **cainjector.serviceAccount.labels** ~ `object`

Optional additional labels to add to the cainjector's Service Account.

#### **cainjector.serviceAccount.automountServiceAccountToken** ~ `bool`
> Default value:
> ```yaml
> true
> ```

Automount API credentials for a Service Account.
#### **cainjector.automountServiceAccountToken** ~ `bool`

Automounting API credentials for a particular pod.

#### **cainjector.volumes** ~ `array`
> Default value:
> ```yaml
> []
> ```

Additional volumes to add to the cert-manager controller pod.
#### **cainjector.volumeMounts** ~ `array`
> Default value:
> ```yaml
> []
> ```

Additional volume mounts to add to the cert-manager controller container.
#### **cainjector.enableServiceLinks** ~ `bool`
> Default value:
> ```yaml
> false
> ```

enableServiceLinks indicates whether information about services should be injected into the pod's environment variables, matching the syntax of Docker links.
### ACME Solver

#### **acmesolver.image.registry** ~ `string`

The container registry to pull the acmesolver image from.

#### **acmesolver.image.repository** ~ `string`
> Default value:
> ```yaml
> quay.io/jetstack/cert-manager-acmesolver
> ```

The container image for the cert-manager acmesolver.

#### **acmesolver.image.tag** ~ `string`

Override the image tag to deploy by setting this variable. If no value is set, the chart's appVersion is used.

#### **acmesolver.image.digest** ~ `string`

Setting a digest will override any tag.

#### **acmesolver.image.pullPolicy** ~ `string`
> Default value:
> ```yaml
> IfNotPresent
> ```

Kubernetes imagePullPolicy on Deployment.
### Startup API Check


This startupapicheck is a Helm post-install hook that waits for the webhook endpoints to become available. The check is implemented using a Kubernetes Job - if you are injecting mesh sidecar proxies into cert-manager pods, ensure that they are not injected into this Job's pod. Otherwise, the installation may time out owing to the Job never being completed because the sidecar proxy does not exit. For more information, see [this note](https://github.com/cert-manager/cert-manager/pull/4414).
#### **startupapicheck.enabled** ~ `bool`
> Default value:
> ```yaml
> true
> ```

Enables the startup api check.
#### **startupapicheck.securityContext** ~ `object`
> Default value:
> ```yaml
> runAsNonRoot: true
> seccompProfile:
>   type: RuntimeDefault
> ```

Pod Security Context to be set on the startupapicheck component Pod. For more information, see [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).

#### **startupapicheck.containerSecurityContext** ~ `object`
> Default value:
> ```yaml
> allowPrivilegeEscalation: false
> capabilities:
>   drop:
>     - ALL
> readOnlyRootFilesystem: true
> ```

Container Security Context to be set on the controller component container. For more information, see [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).

#### **startupapicheck.timeout** ~ `string`
> Default value:
> ```yaml
> 1m
> ```

Timeout for 'kubectl check api' command.
#### **startupapicheck.backoffLimit** ~ `number`
> Default value:
> ```yaml
> 4
> ```

Job backoffLimit
#### **startupapicheck.jobAnnotations** ~ `object`
> Default value:
> ```yaml
> helm.sh/hook: post-install
> helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded
> helm.sh/hook-weight: "1"
> ```

Optional additional annotations to add to the startupapicheck Job.

#### **startupapicheck.podAnnotations** ~ `object`

Optional additional annotations to add to the startupapicheck Pods.

#### **startupapicheck.extraArgs** ~ `array`
> Default value:
> ```yaml
> - -v
> ```

Additional command line flags to pass to startupapicheck binary. To see all available flags run `docker run quay.io/jetstack/cert-manager-startupapicheck:<version> --help`.  
  
Verbose logging is enabled by default so that if startupapicheck fails, you can know what exactly caused the failure. Verbose logs include details of the webhook URL, IP address and TCP connect errors for example.

#### **startupapicheck.extraEnv** ~ `array`
> Default value:
> ```yaml
> []
> ```

Additional environment variables to pass to cert-manager startupapicheck binary.  
For example:

```yaml
extraEnv:
- name: SOME_VAR
  value: 'some value'
```
#### **startupapicheck.resources** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Resources to provide to the cert-manager controller pod.  
  
For example:

```yaml
requests:
  cpu: 10m
  memory: 32Mi
```

For more information, see [Resource Management for Pods and Containers](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/).
#### **startupapicheck.nodeSelector** ~ `object`
> Default value:
> ```yaml
> kubernetes.io/os: linux
> ```

The nodeSelector on Pods tells Kubernetes to schedule Pods on the nodes with matching labels. For more information, see [Assigning Pods to Nodes](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/).  
  
This default ensures that Pods are only scheduled to Linux nodes. It prevents Pods being scheduled to Windows nodes in a mixed OS cluster.

#### **startupapicheck.affinity** ~ `object`
> Default value:
> ```yaml
> {}
> ```

A Kubernetes Affinity, if required. For more information, see [Affinity v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#affinity-v1-core).  
For example:

```yaml
affinity:
  nodeAffinity:
   requiredDuringSchedulingIgnoredDuringExecution:
     nodeSelectorTerms:
     - matchExpressions:
       - key: foo.bar.com/role
         operator: In
         values:
         - master
```
#### **startupapicheck.tolerations** ~ `array`
> Default value:
> ```yaml
> []
> ```

A list of Kubernetes Tolerations, if required. For more information, see [Toleration v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#toleration-v1-core).  
  
For example:

```yaml
tolerations:
- key: foo.bar.com/role
  operator: Equal
  value: master
  effect: NoSchedule
```
#### **startupapicheck.podLabels** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Optional additional labels to add to the startupapicheck Pods.
#### **startupapicheck.image.registry** ~ `string`

The container registry to pull the startupapicheck image from.

#### **startupapicheck.image.repository** ~ `string`
> Default value:
> ```yaml
> quay.io/jetstack/cert-manager-startupapicheck
> ```

The container image for the cert-manager startupapicheck.

#### **startupapicheck.image.tag** ~ `string`

Override the image tag to deploy by setting this variable. If no value is set, the chart's appVersion is used.

#### **startupapicheck.image.digest** ~ `string`

Setting a digest will override any tag.

#### **startupapicheck.image.pullPolicy** ~ `string`
> Default value:
> ```yaml
> IfNotPresent
> ```

Kubernetes imagePullPolicy on Deployment.
#### **startupapicheck.rbac.annotations** ~ `object`
> Default value:
> ```yaml
> helm.sh/hook: post-install
> helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded
> helm.sh/hook-weight: "-5"
> ```

annotations for the startup API Check job RBAC and PSP resources.

#### **startupapicheck.automountServiceAccountToken** ~ `bool`

Automounting API credentials for a particular pod.

#### **startupapicheck.serviceAccount.create** ~ `bool`
> Default value:
> ```yaml
> true
> ```

Specifies whether a service account should be created.
#### **startupapicheck.serviceAccount.name** ~ `string`

The name of the service account to use.  
If not set and create is true, a name is generated using the fullname template.

#### **startupapicheck.serviceAccount.annotations** ~ `object`
> Default value:
> ```yaml
> helm.sh/hook: post-install
> helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded
> helm.sh/hook-weight: "-5"
> ```

Optional additional annotations to add to the Job's Service Account.

#### **startupapicheck.serviceAccount.automountServiceAccountToken** ~ `bool`
> Default value:
> ```yaml
> true
> ```

Automount API credentials for a Service Account.

#### **startupapicheck.serviceAccount.labels** ~ `object`

Optional additional labels to add to the startupapicheck's Service Account.

#### **startupapicheck.volumes** ~ `array`
> Default value:
> ```yaml
> []
> ```

Additional volumes to add to the cert-manager controller pod.
#### **startupapicheck.volumeMounts** ~ `array`
> Default value:
> ```yaml
> []
> ```

Additional volume mounts to add to the cert-manager controller container.
#### **startupapicheck.enableServiceLinks** ~ `bool`
> Default value:
> ```yaml
> false
> ```

enableServiceLinks indicates whether information about services should be injected into pod's environment variables, matching the syntax of Docker links.
#### **extraObjects** ~ `array`
> Default value:
> ```yaml
> []
> ```

Create dynamic manifests via values.  
  
For example:

```yaml
extraObjects:
  - |
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: '{{ template "cert-manager.fullname" . }}-extra-configmap'
```

<!-- /AUTO-GENERATED -->
### Default Security Contexts

The default pod-level and container-level security contexts, below, adhere to the [restricted](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted) Pod Security Standards policies.

Default pod-level securityContext:
```yaml
runAsNonRoot: true
seccompProfile:
  type: RuntimeDefault
```

Default containerSecurityContext:
```yaml
allowPrivilegeEscalation: false
capabilities:
  drop:
  - ALL
```

### Assigning Values

Specify each parameter using the `--set key=value[,key=value]` argument to `helm install`.

Alternatively, a YAML file that specifies the values for the above parameters can be provided while installing the chart. For example,

```console
$ helm install my-release -f values.yaml .
```
> **Tip**: You can use the default [values.yaml](https://github.com/cert-manager/cert-manager/blob/master/deploy/charts/cert-manager/values.yaml)

## Contributing

This chart is maintained at [github.com/cert-manager/cert-manager](https://github.com/cert-manager/cert-manager/tree/master/deploy/charts/cert-manager).
