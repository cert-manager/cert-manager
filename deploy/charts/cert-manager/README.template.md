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

To install the chart with the release name `my-release`:

```console
## Add the Jetstack Helm repository
$ helm repo add jetstack https://charts.jetstack.io

## Install the cert-manager helm chart
$ helm install my-release --namespace cert-manager --version {{RELEASE_VERSION}} jetstack/cert-manager
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
$ kubectl delete -f https://github.com/cert-manager/cert-manager/releases/download/{{RELEASE_VERSION}}/cert-manager.crds.yaml
```

## Configuration
<!-- AUTO-GENERATED -->

### Global


<table>
<tr>
<th>Property</th>
<th>Description</th>
<th>Type</th>
<th>Default</th>
</tr>
<tr>

<td>global.imagePullSecrets</td>
<td>

Reference to one or more secrets to be used when pulling images. For more information, see [Pull an Image from a Private Registry](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/).  
  
For example:

```yaml
imagePullSecrets:
  - name: "image-pull-secret"
```

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>global.commonLabels</td>
<td>

Labels to apply to all resources.  
Please note that this does not add labels to the resources created dynamically by the controllers. For these resources, you have to add the labels in the template in the cert-manager custom resource: For example, podTemplate/ ingressTemplate in ACMEChallengeSolverHTTP01Ingress. For more information, see the [cert-manager documentation](https://cert-manager.io/docs/reference/api-docs/#acme.cert-manager.io/v1.ACMEChallengeSolverHTTP01Ingress).  
For example, secretTemplate in CertificateSpec  
For more information, see the [cert-manager documentation](https://cert-manager.io/docs/reference/api-docs/#cert-manager.io/v1.CertificateSpec).

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>global.revisionHistoryLimit</td>
<td>

The number of old ReplicaSets to retain to allow rollback (if not set, the default Kubernetes value is set to 10).


</td>
<td>number</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>global.priorityClassName</td>
<td>

The optional priority class to be used for the cert-manager pods.

</td>
<td>string</td>
<td>

```yaml
""
```

</td>
</tr>
<tr>

<td>global.rbac.create</td>
<td>

Create required ClusterRoles and ClusterRoleBindings for cert-manager.

</td>
<td>bool</td>
<td>

```yaml
true
```

</td>
</tr>
<tr>

<td>global.rbac.aggregateClusterRoles</td>
<td>

Aggregate ClusterRoles to Kubernetes default user-facing roles. For more information, see [User-facing roles](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles)

</td>
<td>bool</td>
<td>

```yaml
true
```

</td>
</tr>
<tr>

<td>global.podSecurityPolicy.enabled</td>
<td>

Create PodSecurityPolicy for cert-manager.  
  
Note that PodSecurityPolicy was deprecated in Kubernetes 1.21 and removed in Kubernetes 1.25.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
<tr>

<td>global.podSecurityPolicy.useAppArmor</td>
<td>

Configure the PodSecurityPolicy to use AppArmor.

</td>
<td>bool</td>
<td>

```yaml
true
```

</td>
</tr>
<tr>

<td>global.logLevel</td>
<td>

Set the verbosity of cert-manager. A range of 0 - 6, with 6 being the most verbose.

</td>
<td>number</td>
<td>

```yaml
2
```

</td>
</tr>
<tr>

<td>global.leaderElection.namespace</td>
<td>

Override the namespace used for the leader election lease.

</td>
<td>string</td>
<td>

```yaml
kube-system
```

</td>
</tr>
<tr>

<td>global.leaderElection.leaseDuration</td>
<td>

The duration that non-leader candidates will wait after observing a leadership renewal until attempting to acquire leadership of a led but unrenewed leader slot. This is effectively the maximum duration that a leader can be stopped before it is replaced by another candidate.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>global.leaderElection.renewDeadline</td>
<td>

The interval between attempts by the acting master to renew a leadership slot before it stops leading. This must be less than or equal to the lease duration.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>global.leaderElection.retryPeriod</td>
<td>

The duration the clients should wait between attempting acquisition and renewal of a leadership.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>installCRDs</td>
<td>

Install the cert-manager CRDs, it is recommended to not use Helm to manage the CRDs.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
</table>

### Controller


<table>
<tr>
<th>Property</th>
<th>Description</th>
<th>Type</th>
<th>Default</th>
</tr>
<tr>

<td>replicaCount</td>
<td>

The number of replicas of the cert-manager controller to run.  
  
The default is 1, but in production set this to 2 or 3 to provide high availability.  
  
If `replicas > 1`, consider setting `podDisruptionBudget.enabled=true`.  
  
Note that cert-manager uses leader election to ensure that there can only be a single instance active at a time.

</td>
<td>number</td>
<td>

```yaml
1
```

</td>
</tr>
<tr>

<td>strategy</td>
<td>

Deployment update strategy for the cert-manager controller deployment. For more information, see the [Kubernetes documentation](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#strategy).  
  
For example:

```yaml
strategy:
  type: RollingUpdate
  rollingUpdate:
    maxSurge: 0
    maxUnavailable: 1
```

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>podDisruptionBudget.enabled</td>
<td>

Enable or disable the PodDisruptionBudget resource.  
  
This prevents downtime during voluntary disruptions such as during a Node upgrade. For example, the PodDisruptionBudget will block `kubectl drain` if it is used on the Node where the only remaining cert-manager  
Pod is currently running.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
<tr>

<td>podDisruptionBudget.minAvailable</td>
<td>

This configures the minimum available pods for disruptions. It can either be set to an integer (e.g. 1) or a percentage value (e.g. 25%).  
It cannot be used if `maxUnavailable` is set.


</td>
<td>number</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>podDisruptionBudget.maxUnavailable</td>
<td>

This configures the maximum unavailable pods for disruptions. It can either be set to an integer (e.g. 1) or a percentage value (e.g. 25%). it cannot be used if `minAvailable` is set.


</td>
<td>number</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>featureGates</td>
<td>

A comma-separated list of feature gates that should be enabled on the controller pod.

</td>
<td>string</td>
<td>

```yaml
""
```

</td>
</tr>
<tr>

<td>maxConcurrentChallenges</td>
<td>

The maximum number of challenges that can be scheduled as 'processing' at once.

</td>
<td>number</td>
<td>

```yaml
60
```

</td>
</tr>
<tr>

<td>image.registry</td>
<td>

The container registry to pull the manager image from.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>image.repository</td>
<td>

The container image for the cert-manager controller.


</td>
<td>string</td>
<td>

```yaml
quay.io/jetstack/cert-manager-controller
```

</td>
</tr>
<tr>

<td>image.tag</td>
<td>

Override the image tag to deploy by setting this variable. If no value is set, the chart's appVersion is used.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>image.digest</td>
<td>

Setting a digest will override any tag.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>image.pullPolicy</td>
<td>

Kubernetes imagePullPolicy on Deployment.

</td>
<td>string</td>
<td>

```yaml
IfNotPresent
```

</td>
</tr>
<tr>

<td>clusterResourceNamespace</td>
<td>

Override the namespace used to store DNS provider credentials etc. for ClusterIssuer resources. By default, the same namespace as cert-manager is deployed within is used. This namespace will not be automatically created by the Helm chart.

</td>
<td>string</td>
<td>

```yaml
""
```

</td>
</tr>
<tr>

<td>namespace</td>
<td>

This namespace allows you to define where the services are installed into. If not set then they use the namespace of the release. This is helpful when installing cert manager as a chart dependency (sub chart).

</td>
<td>string</td>
<td>

```yaml
""
```

</td>
</tr>
<tr>

<td>serviceAccount.create</td>
<td>

Specifies whether a service account should be created.

</td>
<td>bool</td>
<td>

```yaml
true
```

</td>
</tr>
<tr>

<td>serviceAccount.name</td>
<td>

The name of the service account to use.  
If not set and create is true, a name is generated using the fullname template.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>serviceAccount.annotations</td>
<td>

Optional additional annotations to add to the controller's Service Account.


</td>
<td>object</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>serviceAccount.labels</td>
<td>

Optional additional labels to add to the controller's Service Account.


</td>
<td>object</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>serviceAccount.automountServiceAccountToken</td>
<td>

Automount API credentials for a Service Account.

</td>
<td>bool</td>
<td>

```yaml
true
```

</td>
</tr>
<tr>

<td>automountServiceAccountToken</td>
<td>

Automounting API credentials for a particular pod.


</td>
<td>bool</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>enableCertificateOwnerRef</td>
<td>

When this flag is enabled, secrets will be automatically removed when the certificate resource is deleted.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
<tr>

<td>config</td>
<td>

This property is used to configure options for the controller pod. This allows setting options that would usually be provided using flags. An APIVersion and Kind must be specified in your values.yaml file.  
Flags will override options that are set here.  
  
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
  metricsTLSConfig:
    dynamic:
      secretNamespace: "cert-manager"
      secretName: "cert-manager-metrics-ca"
      dnsNames:
      - cert-manager-metrics
      - cert-manager-metrics.cert-manager
      - cert-manager-metrics.cert-manager.svc
```

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>dns01RecursiveNameservers</td>
<td>

A comma-separated string with the host and port of the recursive nameservers cert-manager should query.

</td>
<td>string</td>
<td>

```yaml
""
```

</td>
</tr>
<tr>

<td>dns01RecursiveNameserversOnly</td>
<td>

Forces cert-manager to use only the recursive nameservers for verification. Enabling this option could cause the DNS01 self check to take longer owing to caching performed by the recursive nameservers.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
<tr>

<td>extraArgs</td>
<td>

Additional command line flags to pass to cert-manager controller binary. To see all available flags run `docker run quay.io/jetstack/cert-manager-controller:<version> --help`.  
  
Use this flag to enable or disable arbitrary controllers. For example, to disable the CertificiateRequests approver.  
  
For example:

```yaml
extraArgs:
  - --controllers=*,-certificaterequests-approver
```

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>extraEnv</td>
<td>

Additional environment variables to pass to cert-manager controller binary.

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>resources</td>
<td>

Resources to provide to the cert-manager controller pod.  
  
For example:

```yaml
requests:
  cpu: 10m
  memory: 32Mi
```

For more information, see [Resource Management for Pods and Containers](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/).

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>securityContext</td>
<td>

Pod Security Context.  
For more information, see [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).


</td>
<td>object</td>
<td>

```yaml
runAsNonRoot: true
seccompProfile:
  type: RuntimeDefault
```

</td>
</tr>
<tr>

<td>containerSecurityContext</td>
<td>

Container Security Context to be set on the controller component container. For more information, see [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).


</td>
<td>object</td>
<td>

```yaml
allowPrivilegeEscalation: false
capabilities:
  drop:
    - ALL
readOnlyRootFilesystem: true
```

</td>
</tr>
<tr>

<td>volumes</td>
<td>

Additional volumes to add to the cert-manager controller pod.

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>volumeMounts</td>
<td>

Additional volume mounts to add to the cert-manager controller container.

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>deploymentAnnotations</td>
<td>

Optional additional annotations to add to the controller Deployment.


</td>
<td>object</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>podAnnotations</td>
<td>

Optional additional annotations to add to the controller Pods.


</td>
<td>object</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>podLabels</td>
<td>

Optional additional labels to add to the controller Pods.

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>serviceAnnotations</td>
<td>

Optional annotations to add to the controller Service.


</td>
<td>object</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>serviceLabels</td>
<td>

Optional additional labels to add to the controller Service.


</td>
<td>object</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>podDnsPolicy</td>
<td>

Pod DNS policy.  
For more information, see [Pod's DNS Policy](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-s-dns-policy).


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>podDnsConfig</td>
<td>

Pod DNS configuration. The podDnsConfig field is optional and can work with any podDnsPolicy settings. However, when a Pod's dnsPolicy is set to "None", the dnsConfig field has to be specified. For more information, see [Pod's DNS Config](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-dns-config).


</td>
<td>object</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>nodeSelector</td>
<td>

The nodeSelector on Pods tells Kubernetes to schedule Pods on the nodes with matching labels. For more information, see [Assigning Pods to Nodes](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/).  
  
This default ensures that Pods are only scheduled to Linux nodes. It prevents Pods being scheduled to Windows nodes in a mixed OS cluster.


</td>
<td>object</td>
<td>

```yaml
kubernetes.io/os: linux
```

</td>
</tr>
<tr>

<td>ingressShim.defaultIssuerName</td>
<td>

Optional default issuer to use for ingress resources.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>ingressShim.defaultIssuerKind</td>
<td>

Optional default issuer kind to use for ingress resources.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>ingressShim.defaultIssuerGroup</td>
<td>

Optional default issuer group to use for ingress resources.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>http_proxy</td>
<td>

Configures the HTTP_PROXY environment variable where a HTTP proxy is required.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>https_proxy</td>
<td>

Configures the HTTPS_PROXY environment variable where a HTTP proxy is required.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>no_proxy</td>
<td>

Configures the NO_PROXY environment variable where a HTTP proxy is required, but certain domains should be excluded.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>affinity</td>
<td>

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

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>tolerations</td>
<td>

A list of Kubernetes Tolerations, if required. For more information, see [Toleration v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#toleration-v1-core).  
  
For example:

```yaml
tolerations:
- key: foo.bar.com/role
  operator: Equal
  value: master
  effect: NoSchedule
```

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>topologySpreadConstraints</td>
<td>

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

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>livenessProbe</td>
<td>

LivenessProbe settings for the controller container of the controller Pod.  
  
This is enabled by default, in order to enable the clock-skew liveness probe that restarts the controller in case of a skew between the system clock and the monotonic clock. LivenessProbe durations and thresholds are based on those used for the Kubernetes controller-manager. For more information see the following on the  
[Kubernetes GitHub repository](https://github.com/kubernetes/kubernetes/blob/806b30170c61a38fedd54cc9ede4cd6275a1ad3b/cmd/kubeadm/app/util/staticpod/utils.go#L241-L245)


</td>
<td>object</td>
<td>

```yaml
enabled: true
failureThreshold: 8
initialDelaySeconds: 10
periodSeconds: 10
successThreshold: 1
timeoutSeconds: 15
```

</td>
</tr>
<tr>

<td>enableServiceLinks</td>
<td>

enableServiceLinks indicates whether information about services should be injected into the pod's environment variables, matching the syntax of Docker links.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
</table>

### Prometheus


<table>
<tr>
<th>Property</th>
<th>Description</th>
<th>Type</th>
<th>Default</th>
</tr>
<tr>

<td>prometheus.enabled</td>
<td>

Enable Prometheus monitoring for the cert-manager controller to use with the. Prometheus Operator. Either `prometheus.servicemonitor.enabled` or  
`prometheus.podmonitor.enabled` can be used to create a ServiceMonitor/PodMonitor  
resource.

</td>
<td>bool</td>
<td>

```yaml
true
```

</td>
</tr>
<tr>

<td>prometheus.servicemonitor.enabled</td>
<td>

Create a ServiceMonitor to add cert-manager to Prometheus.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
<tr>

<td>prometheus.servicemonitor.prometheusInstance</td>
<td>

Specifies the `prometheus` label on the created ServiceMonitor. This is used when different Prometheus instances have label selectors matching different ServiceMonitors.

</td>
<td>string</td>
<td>

```yaml
default
```

</td>
</tr>
<tr>

<td>prometheus.servicemonitor.targetPort</td>
<td>

The target port to set on the ServiceMonitor. This must match the port that the cert-manager controller is listening on for metrics.

</td>
<td>number</td>
<td>

```yaml
9402
```

</td>
</tr>
<tr>

<td>prometheus.servicemonitor.path</td>
<td>

The path to scrape for metrics.

</td>
<td>string</td>
<td>

```yaml
/metrics
```

</td>
</tr>
<tr>

<td>prometheus.servicemonitor.interval</td>
<td>

The interval to scrape metrics.

</td>
<td>string</td>
<td>

```yaml
60s
```

</td>
</tr>
<tr>

<td>prometheus.servicemonitor.scrapeTimeout</td>
<td>

The timeout before a metrics scrape fails.

</td>
<td>string</td>
<td>

```yaml
30s
```

</td>
</tr>
<tr>

<td>prometheus.servicemonitor.labels</td>
<td>

Additional labels to add to the ServiceMonitor.

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>prometheus.servicemonitor.annotations</td>
<td>

Additional annotations to add to the ServiceMonitor.

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>prometheus.servicemonitor.honorLabels</td>
<td>

Keep labels from scraped data, overriding server-side labels.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
<tr>

<td>prometheus.servicemonitor.endpointAdditionalProperties</td>
<td>

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




</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>prometheus.podmonitor.enabled</td>
<td>

Create a PodMonitor to add cert-manager to Prometheus.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
<tr>

<td>prometheus.podmonitor.prometheusInstance</td>
<td>

Specifies the `prometheus` label on the created PodMonitor. This is used when different Prometheus instances have label selectors matching different PodMonitors.

</td>
<td>string</td>
<td>

```yaml
default
```

</td>
</tr>
<tr>

<td>prometheus.podmonitor.path</td>
<td>

The path to scrape for metrics.

</td>
<td>string</td>
<td>

```yaml
/metrics
```

</td>
</tr>
<tr>

<td>prometheus.podmonitor.interval</td>
<td>

The interval to scrape metrics.

</td>
<td>string</td>
<td>

```yaml
60s
```

</td>
</tr>
<tr>

<td>prometheus.podmonitor.scrapeTimeout</td>
<td>

The timeout before a metrics scrape fails.

</td>
<td>string</td>
<td>

```yaml
30s
```

</td>
</tr>
<tr>

<td>prometheus.podmonitor.labels</td>
<td>

Additional labels to add to the PodMonitor.

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>prometheus.podmonitor.annotations</td>
<td>

Additional annotations to add to the PodMonitor.

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>prometheus.podmonitor.honorLabels</td>
<td>

Keep labels from scraped data, overriding server-side labels.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
<tr>

<td>prometheus.podmonitor.endpointAdditionalProperties</td>
<td>

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




</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
</table>

### Webhook


<table>
<tr>
<th>Property</th>
<th>Description</th>
<th>Type</th>
<th>Default</th>
</tr>
<tr>

<td>webhook.replicaCount</td>
<td>

Number of replicas of the cert-manager webhook to run.  
  
The default is 1, but in production set this to 2 or 3 to provide high availability.  
  
If `replicas > 1`, consider setting `webhook.podDisruptionBudget.enabled=true`.

</td>
<td>number</td>
<td>

```yaml
1
```

</td>
</tr>
<tr>

<td>webhook.timeoutSeconds</td>
<td>

The number of seconds the API server should wait for the webhook to respond before treating the call as a failure. The value must be between 1 and 30 seconds. For more information, see  
[Validating webhook configuration v1](https://kubernetes.io/docs/reference/kubernetes-api/extend-resources/validating-webhook-configuration-v1/).  
  
The default is set to the maximum value of 30 seconds as users sometimes report that the connection between the K8S API server and the cert-manager webhook server times out. If *this* timeout is reached, the error message will be "context deadline exceeded", which doesn't help the user diagnose what phase of the HTTPS connection timed out. For example, it could be during DNS resolution, TCP connection, TLS negotiation, HTTP negotiation, or slow HTTP response from the webhook server. By setting this timeout to its maximum value the underlying timeout error message has more chance of being returned to the end user.

</td>
<td>number</td>
<td>

```yaml
30
```

</td>
</tr>
<tr>

<td>webhook.config</td>
<td>

This is used to configure options for the webhook pod. This allows setting options that would usually be provided using flags. An APIVersion and Kind must be specified in your values.yaml file.  
Flags override options that are set here.  
  
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
```

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>webhook.strategy</td>
<td>

The update strategy for the cert-manager webhook deployment. For more information, see the [Kubernetes documentation](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#strategy)  
  
For example:

```yaml
strategy:
  type: RollingUpdate
  rollingUpdate:
    maxSurge: 0
    maxUnavailable: 1
```

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>webhook.securityContext</td>
<td>

Pod Security Context to be set on the webhook component Pod. For more information, see [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).


</td>
<td>object</td>
<td>

```yaml
runAsNonRoot: true
seccompProfile:
  type: RuntimeDefault
```

</td>
</tr>
<tr>

<td>webhook.containerSecurityContext</td>
<td>

Container Security Context to be set on the webhook component container. For more information, see [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).


</td>
<td>object</td>
<td>

```yaml
allowPrivilegeEscalation: false
capabilities:
  drop:
    - ALL
readOnlyRootFilesystem: true
```

</td>
</tr>
<tr>

<td>webhook.podDisruptionBudget.enabled</td>
<td>

Enable or disable the PodDisruptionBudget resource.  
  
This prevents downtime during voluntary disruptions such as during a Node upgrade. For example, the PodDisruptionBudget will block `kubectl drain` if it is used on the Node where the only remaining cert-manager  
Pod is currently running.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
<tr>

<td>webhook.podDisruptionBudget.minAvailable</td>
<td>

This property configures the minimum available pods for disruptions. Can either be set to an integer (e.g. 1) or a percentage value (e.g. 25%).  
It cannot be used if `maxUnavailable` is set.


</td>
<td>number</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>webhook.podDisruptionBudget.maxUnavailable</td>
<td>

This property configures the maximum unavailable pods for disruptions. Can either be set to an integer (e.g. 1) or a percentage value (e.g. 25%).  
It cannot be used if `minAvailable` is set.


</td>
<td>number</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>webhook.deploymentAnnotations</td>
<td>

Optional additional annotations to add to the webhook Deployment.


</td>
<td>object</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>webhook.podAnnotations</td>
<td>

Optional additional annotations to add to the webhook Pods.


</td>
<td>object</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>webhook.serviceAnnotations</td>
<td>

Optional additional annotations to add to the webhook Service.


</td>
<td>object</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>webhook.mutatingWebhookConfigurationAnnotations</td>
<td>

Optional additional annotations to add to the webhook MutatingWebhookConfiguration.


</td>
<td>object</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>webhook.validatingWebhookConfigurationAnnotations</td>
<td>

Optional additional annotations to add to the webhook ValidatingWebhookConfiguration.


</td>
<td>object</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>webhook.validatingWebhookConfiguration.namespaceSelector</td>
<td>

Configure spec.namespaceSelector for validating webhooks.


</td>
<td>object</td>
<td>

```yaml
matchExpressions:
  - key: cert-manager.io/disable-validation
    operator: NotIn
    values:
      - "true"
```

</td>
</tr>
<tr>

<td>webhook.mutatingWebhookConfiguration.namespaceSelector</td>
<td>

Configure spec.namespaceSelector for mutating webhooks.


</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>webhook.extraArgs</td>
<td>

Additional command line flags to pass to cert-manager webhook binary. To see all available flags run `docker run quay.io/jetstack/cert-manager-webhook:<version> --help`.

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>webhook.featureGates</td>
<td>

Comma separated list of feature gates that should be enabled on the webhook pod.

</td>
<td>string</td>
<td>

```yaml
""
```

</td>
</tr>
<tr>

<td>webhook.resources</td>
<td>

Resources to provide to the cert-manager webhook pod.  
  
For example:

```yaml
requests:
  cpu: 10m
  memory: 32Mi
```

For more information, see [Resource Management for Pods and Containers](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/).

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>webhook.livenessProbe</td>
<td>

Liveness probe values.  
For more information, see [Container probes](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#container-probes).


</td>
<td>object</td>
<td>

```yaml
failureThreshold: 3
initialDelaySeconds: 60
periodSeconds: 10
successThreshold: 1
timeoutSeconds: 1
```

</td>
</tr>
<tr>

<td>webhook.readinessProbe</td>
<td>

Readiness probe values.  
For more information, see [Container probes](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#container-probes).


</td>
<td>object</td>
<td>

```yaml
failureThreshold: 3
initialDelaySeconds: 5
periodSeconds: 5
successThreshold: 1
timeoutSeconds: 1
```

</td>
</tr>
<tr>

<td>webhook.nodeSelector</td>
<td>

The nodeSelector on Pods tells Kubernetes to schedule Pods on the nodes with matching labels. For more information, see [Assigning Pods to Nodes](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/).  
  
This default ensures that Pods are only scheduled to Linux nodes. It prevents Pods being scheduled to Windows nodes in a mixed OS cluster.


</td>
<td>object</td>
<td>

```yaml
kubernetes.io/os: linux
```

</td>
</tr>
<tr>

<td>webhook.affinity</td>
<td>

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

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>webhook.tolerations</td>
<td>

A list of Kubernetes Tolerations, if required. For more information, see [Toleration v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#toleration-v1-core).  
  
For example:

```yaml
tolerations:
- key: foo.bar.com/role
  operator: Equal
  value: master
  effect: NoSchedule
```

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>webhook.topologySpreadConstraints</td>
<td>

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

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>webhook.podLabels</td>
<td>

Optional additional labels to add to the Webhook Pods.

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>webhook.serviceLabels</td>
<td>

Optional additional labels to add to the Webhook Service.

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>webhook.image.registry</td>
<td>

The container registry to pull the webhook image from.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>webhook.image.repository</td>
<td>

The container image for the cert-manager webhook


</td>
<td>string</td>
<td>

```yaml
quay.io/jetstack/cert-manager-webhook
```

</td>
</tr>
<tr>

<td>webhook.image.tag</td>
<td>

Override the image tag to deploy by setting this variable. If no value is set, the chart's appVersion will be used.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>webhook.image.digest</td>
<td>

Setting a digest will override any tag


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>webhook.image.pullPolicy</td>
<td>

Kubernetes imagePullPolicy on Deployment.

</td>
<td>string</td>
<td>

```yaml
IfNotPresent
```

</td>
</tr>
<tr>

<td>webhook.serviceAccount.create</td>
<td>

Specifies whether a service account should be created.

</td>
<td>bool</td>
<td>

```yaml
true
```

</td>
</tr>
<tr>

<td>webhook.serviceAccount.name</td>
<td>

The name of the service account to use.  
If not set and create is true, a name is generated using the fullname template.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>webhook.serviceAccount.annotations</td>
<td>

Optional additional annotations to add to the controller's Service Account.


</td>
<td>object</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>webhook.serviceAccount.labels</td>
<td>

Optional additional labels to add to the webhook's Service Account.


</td>
<td>object</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>webhook.serviceAccount.automountServiceAccountToken</td>
<td>

Automount API credentials for a Service Account.

</td>
<td>bool</td>
<td>

```yaml
true
```

</td>
</tr>
<tr>

<td>webhook.automountServiceAccountToken</td>
<td>

Automounting API credentials for a particular pod.


</td>
<td>bool</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>webhook.securePort</td>
<td>

The port that the webhook listens on for requests. In GKE private clusters, by default Kubernetes apiservers are allowed to talk to the cluster nodes only on 443 and 10250. Configuring securePort: 10250, therefore will work out-of-the-box without needing to add firewall rules or requiring NET_BIND_SERVICE capabilities to bind port numbers <1000.

</td>
<td>number</td>
<td>

```yaml
10250
```

</td>
</tr>
<tr>

<td>webhook.hostNetwork</td>
<td>

Specifies if the webhook should be started in hostNetwork mode.  
  
Required for use in some managed kubernetes clusters (such as AWS EKS) with custom. CNI (such as calico), because control-plane managed by AWS cannot communicate with pods' IP CIDR and admission webhooks are not working  
  
Since the default port for the webhook conflicts with kubelet on the host network, `webhook.securePort` should be changed to an available port if running in hostNetwork mode.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
<tr>

<td>webhook.serviceType</td>
<td>

Specifies how the service should be handled. Useful if you want to expose the webhook outside of the cluster. In some cases, the control plane cannot reach internal services.

</td>
<td>string</td>
<td>

```yaml
ClusterIP
```

</td>
</tr>
<tr>

<td>webhook.loadBalancerIP</td>
<td>

Specify the load balancer IP for the created service.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>webhook.url</td>
<td>

Overrides the mutating webhook and validating webhook so they reach the webhook service using the `url` field instead of a service.

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>webhook.networkPolicy.enabled</td>
<td>

Create network policies for the webhooks.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
<tr>

<td>webhook.networkPolicy.ingress</td>
<td>

Ingress rule for the webhook network policy. By default, it allows all inbound traffic.


</td>
<td>array</td>
<td>

```yaml
- from:
    - ipBlock:
        cidr: 0.0.0.0/0
```

</td>
</tr>
<tr>

<td>webhook.networkPolicy.egress</td>
<td>

Egress rule for the webhook network policy. By default, it allows all outbound traffic to ports 80 and 443, as well as DNS ports.


</td>
<td>array</td>
<td>

```yaml
- ports:
    - port: 80
      protocol: TCP
    - port: 443
      protocol: TCP
    - port: 53
      protocol: TCP
    - port: 53
      protocol: UDP
    - port: 6443
      protocol: TCP
  to:
    - ipBlock:
        cidr: 0.0.0.0/0
```

</td>
</tr>
<tr>

<td>webhook.volumes</td>
<td>

Additional volumes to add to the cert-manager controller pod.

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>webhook.volumeMounts</td>
<td>

Additional volume mounts to add to the cert-manager controller container.

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>webhook.enableServiceLinks</td>
<td>

enableServiceLinks indicates whether information about services should be injected into the pod's environment variables, matching the syntax of Docker links.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
</table>

### CA Injector


<table>
<tr>
<th>Property</th>
<th>Description</th>
<th>Type</th>
<th>Default</th>
</tr>
<tr>

<td>cainjector.enabled</td>
<td>

Create the CA Injector deployment

</td>
<td>bool</td>
<td>

```yaml
true
```

</td>
</tr>
<tr>

<td>cainjector.replicaCount</td>
<td>

The number of replicas of the cert-manager cainjector to run.  
  
The default is 1, but in production set this to 2 or 3 to provide high availability.  
  
If `replicas > 1`, consider setting `cainjector.podDisruptionBudget.enabled=true`.  
  
Note that cert-manager uses leader election to ensure that there can only be a single instance active at a time.

</td>
<td>number</td>
<td>

```yaml
1
```

</td>
</tr>
<tr>

<td>cainjector.config</td>
<td>

This is used to configure options for the cainjector pod. It allows setting options that are usually provided via flags. An APIVersion and Kind must be specified in your values.yaml file.  
Flags override options that are set here.  
  
For example:

```yaml
apiVersion: cainjector.config.cert-manager.io/v1alpha1
kind: CAInjectorConfiguration
logging:
 verbosity: 2
 format: text
leaderElectionConfig:
 namespace: kube-system
```

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>cainjector.strategy</td>
<td>

Deployment update strategy for the cert-manager cainjector deployment. For more information, see the [Kubernetes documentation](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#strategy).  
  
For example:

```yaml
strategy:
  type: RollingUpdate
  rollingUpdate:
    maxSurge: 0
    maxUnavailable: 1
```

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>cainjector.securityContext</td>
<td>

Pod Security Context to be set on the cainjector component Pod. For more information, see [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).


</td>
<td>object</td>
<td>

```yaml
runAsNonRoot: true
seccompProfile:
  type: RuntimeDefault
```

</td>
</tr>
<tr>

<td>cainjector.containerSecurityContext</td>
<td>

Container Security Context to be set on the cainjector component container. For more information, see [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).


</td>
<td>object</td>
<td>

```yaml
allowPrivilegeEscalation: false
capabilities:
  drop:
    - ALL
readOnlyRootFilesystem: true
```

</td>
</tr>
<tr>

<td>cainjector.podDisruptionBudget.enabled</td>
<td>

Enable or disable the PodDisruptionBudget resource.  
  
This prevents downtime during voluntary disruptions such as during a Node upgrade. For example, the PodDisruptionBudget will block `kubectl drain` if it is used on the Node where the only remaining cert-manager  
Pod is currently running.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
<tr>

<td>cainjector.podDisruptionBudget.minAvailable</td>
<td>

`minAvailable` configures the minimum available pods for disruptions. It can either be set to  
an integer (e.g. 1) or a percentage value (e.g. 25%).  
Cannot be used if `maxUnavailable` is set.


</td>
<td>number</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>cainjector.podDisruptionBudget.maxUnavailable</td>
<td>

`maxUnavailable` configures the maximum unavailable pods for disruptions. It can either be set to  
an integer (e.g. 1) or a percentage value (e.g. 25%).  
Cannot be used if `minAvailable` is set.


</td>
<td>number</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>cainjector.deploymentAnnotations</td>
<td>

Optional additional annotations to add to the cainjector Deployment.


</td>
<td>object</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>cainjector.podAnnotations</td>
<td>

Optional additional annotations to add to the cainjector Pods.


</td>
<td>object</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>cainjector.extraArgs</td>
<td>

Additional command line flags to pass to cert-manager cainjector binary. To see all available flags run `docker run quay.io/jetstack/cert-manager-cainjector:<version> --help`.

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>cainjector.featureGates</td>
<td>

Comma separated list of feature gates that should be enabled on the cainjector pod.

</td>
<td>string</td>
<td>

```yaml
""
```

</td>
</tr>
<tr>

<td>cainjector.resources</td>
<td>

Resources to provide to the cert-manager cainjector pod.  
  
For example:

```yaml
requests:
  cpu: 10m
  memory: 32Mi
```

For more information, see [Resource Management for Pods and Containers](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/).

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>cainjector.nodeSelector</td>
<td>

The nodeSelector on Pods tells Kubernetes to schedule Pods on the nodes with matching labels. For more information, see [Assigning Pods to Nodes](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/).  
  
This default ensures that Pods are only scheduled to Linux nodes. It prevents Pods being scheduled to Windows nodes in a mixed OS cluster.


</td>
<td>object</td>
<td>

```yaml
kubernetes.io/os: linux
```

</td>
</tr>
<tr>

<td>cainjector.affinity</td>
<td>

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

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>cainjector.tolerations</td>
<td>

A list of Kubernetes Tolerations, if required. For more information, see [Toleration v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#toleration-v1-core).  
  
For example:

```yaml
tolerations:
- key: foo.bar.com/role
  operator: Equal
  value: master
  effect: NoSchedule
```

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>cainjector.topologySpreadConstraints</td>
<td>

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

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>cainjector.podLabels</td>
<td>

Optional additional labels to add to the CA Injector Pods.

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>cainjector.image.registry</td>
<td>

The container registry to pull the cainjector image from.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>cainjector.image.repository</td>
<td>

The container image for the cert-manager cainjector


</td>
<td>string</td>
<td>

```yaml
quay.io/jetstack/cert-manager-controller
```

</td>
</tr>
<tr>

<td>cainjector.image.tag</td>
<td>

Override the image tag to deploy by setting this variable. If no value is set, the chart's appVersion will be used.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>cainjector.image.digest</td>
<td>

Setting a digest will override any tag.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>cainjector.image.pullPolicy</td>
<td>

Kubernetes imagePullPolicy on Deployment.

</td>
<td>string</td>
<td>

```yaml
IfNotPresent
```

</td>
</tr>
<tr>

<td>cainjector.serviceAccount.create</td>
<td>

Specifies whether a service account should be created.

</td>
<td>bool</td>
<td>

```yaml
true
```

</td>
</tr>
<tr>

<td>cainjector.serviceAccount.name</td>
<td>

The name of the service account to use.  
If not set and create is true, a name is generated using the fullname template


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>cainjector.serviceAccount.annotations</td>
<td>

Optional additional annotations to add to the controller's Service Account.


</td>
<td>object</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>cainjector.serviceAccount.labels</td>
<td>

Optional additional labels to add to the cainjector's Service Account.


</td>
<td>object</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>cainjector.serviceAccount.automountServiceAccountToken</td>
<td>

Automount API credentials for a Service Account.

</td>
<td>bool</td>
<td>

```yaml
true
```

</td>
</tr>
<tr>

<td>cainjector.automountServiceAccountToken</td>
<td>

Automounting API credentials for a particular pod.


</td>
<td>bool</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>cainjector.volumes</td>
<td>

Additional volumes to add to the cert-manager controller pod.

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>cainjector.volumeMounts</td>
<td>

Additional volume mounts to add to the cert-manager controller container.

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>cainjector.enableServiceLinks</td>
<td>

enableServiceLinks indicates whether information about services should be injected into the pod's environment variables, matching the syntax of Docker links.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
</table>

### ACME Solver


<table>
<tr>
<th>Property</th>
<th>Description</th>
<th>Type</th>
<th>Default</th>
</tr>
<tr>

<td>acmesolver.image.registry</td>
<td>

The container registry to pull the acmesolver image from.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>acmesolver.image.repository</td>
<td>

The container image for the cert-manager acmesolver.


</td>
<td>string</td>
<td>

```yaml
quay.io/jetstack/cert-manager-acmesolver
```

</td>
</tr>
<tr>

<td>acmesolver.image.tag</td>
<td>

Override the image tag to deploy by setting this variable. If no value is set, the chart's appVersion is used.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>acmesolver.image.digest</td>
<td>

Setting a digest will override any tag.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>acmesolver.image.pullPolicy</td>
<td>

Kubernetes imagePullPolicy on Deployment.

</td>
<td>string</td>
<td>

```yaml
IfNotPresent
```

</td>
</tr>
</table>

### Startup API Check


This startupapicheck is a Helm post-install hook that waits for the webhook endpoints to become available. The check is implemented using a Kubernetes Job - if you are injecting mesh sidecar proxies into cert-manager pods, ensure that they are not injected into this Job's pod. Otherwise, the installation may time out owing to the Job never being completed because the sidecar proxy does not exit. For more information, see [this note](https://github.com/cert-manager/cert-manager/pull/4414).

<table>
<tr>
<th>Property</th>
<th>Description</th>
<th>Type</th>
<th>Default</th>
</tr>
<tr>

<td>startupapicheck.enabled</td>
<td>

Enables the startup api check.

</td>
<td>bool</td>
<td>

```yaml
true
```

</td>
</tr>
<tr>

<td>startupapicheck.securityContext</td>
<td>

Pod Security Context to be set on the startupapicheck component Pod. For more information, see [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).


</td>
<td>object</td>
<td>

```yaml
runAsNonRoot: true
seccompProfile:
  type: RuntimeDefault
```

</td>
</tr>
<tr>

<td>startupapicheck.containerSecurityContext</td>
<td>

Container Security Context to be set on the controller component container. For more information, see [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).


</td>
<td>object</td>
<td>

```yaml
allowPrivilegeEscalation: false
capabilities:
  drop:
    - ALL
readOnlyRootFilesystem: true
```

</td>
</tr>
<tr>

<td>startupapicheck.timeout</td>
<td>

Timeout for 'kubectl check api' command.

</td>
<td>string</td>
<td>

```yaml
1m
```

</td>
</tr>
<tr>

<td>startupapicheck.backoffLimit</td>
<td>

Job backoffLimit

</td>
<td>number</td>
<td>

```yaml
4
```

</td>
</tr>
<tr>

<td>startupapicheck.jobAnnotations</td>
<td>

Optional additional annotations to add to the startupapicheck Job.


</td>
<td>object</td>
<td>

```yaml
helm.sh/hook: post-install
helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded
helm.sh/hook-weight: "1"
```

</td>
</tr>
<tr>

<td>startupapicheck.podAnnotations</td>
<td>

Optional additional annotations to add to the startupapicheck Pods.


</td>
<td>object</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>startupapicheck.extraArgs</td>
<td>

Additional command line flags to pass to startupapicheck binary. To see all available flags run `docker run quay.io/jetstack/cert-manager-ctl:<version> --help`.  
  
Verbose logging is enabled by default so that if startupapicheck fails, you can know what exactly caused the failure. Verbose logs include details of the webhook URL, IP address and TCP connect errors for example.


</td>
<td>array</td>
<td>

```yaml
- -v
```

</td>
</tr>
<tr>

<td>startupapicheck.resources</td>
<td>

Resources to provide to the cert-manager controller pod.  
  
For example:

```yaml
requests:
  cpu: 10m
  memory: 32Mi
```

For more information, see [Resource Management for Pods and Containers](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/).

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>startupapicheck.nodeSelector</td>
<td>

The nodeSelector on Pods tells Kubernetes to schedule Pods on the nodes with matching labels. For more information, see [Assigning Pods to Nodes](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/).  
  
This default ensures that Pods are only scheduled to Linux nodes. It prevents Pods being scheduled to Windows nodes in a mixed OS cluster.


</td>
<td>object</td>
<td>

```yaml
kubernetes.io/os: linux
```

</td>
</tr>
<tr>

<td>startupapicheck.affinity</td>
<td>

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

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>startupapicheck.tolerations</td>
<td>

A list of Kubernetes Tolerations, if required. For more information, see [Toleration v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#toleration-v1-core).  
  
For example:

```yaml
tolerations:
- key: foo.bar.com/role
  operator: Equal
  value: master
  effect: NoSchedule
```

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>startupapicheck.podLabels</td>
<td>

Optional additional labels to add to the startupapicheck Pods.

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>startupapicheck.image.registry</td>
<td>

The container registry to pull the startupapicheck image from.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>startupapicheck.image.repository</td>
<td>

The container image for the cert-manager startupapicheck.


</td>
<td>string</td>
<td>

```yaml
quay.io/jetstack/cert-manager-startupapicheck
```

</td>
</tr>
<tr>

<td>startupapicheck.image.tag</td>
<td>

Override the image tag to deploy by setting this variable. If no value is set, the chart's appVersion is used.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>startupapicheck.image.digest</td>
<td>

Setting a digest will override any tag.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>startupapicheck.image.pullPolicy</td>
<td>

Kubernetes imagePullPolicy on Deployment.

</td>
<td>string</td>
<td>

```yaml
IfNotPresent
```

</td>
</tr>
<tr>

<td>startupapicheck.rbac.annotations</td>
<td>

annotations for the startup API Check job RBAC and PSP resources.


</td>
<td>object</td>
<td>

```yaml
helm.sh/hook: post-install
helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded
helm.sh/hook-weight: "-5"
```

</td>
</tr>
<tr>

<td>startupapicheck.automountServiceAccountToken</td>
<td>

Automounting API credentials for a particular pod.


</td>
<td>bool</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>startupapicheck.serviceAccount.create</td>
<td>

Specifies whether a service account should be created.

</td>
<td>bool</td>
<td>

```yaml
true
```

</td>
</tr>
<tr>

<td>startupapicheck.serviceAccount.name</td>
<td>

The name of the service account to use.  
If not set and create is true, a name is generated using the fullname template.


</td>
<td>string</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>startupapicheck.serviceAccount.annotations</td>
<td>

Optional additional annotations to add to the Job's Service Account.


</td>
<td>object</td>
<td>

```yaml
helm.sh/hook: post-install
helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded
helm.sh/hook-weight: "-5"
```

</td>
</tr>
<tr>

<td>startupapicheck.serviceAccount.automountServiceAccountToken</td>
<td>

Automount API credentials for a Service Account.


</td>
<td>bool</td>
<td>

```yaml
true
```

</td>
</tr>
<tr>

<td>startupapicheck.serviceAccount.labels</td>
<td>

Optional additional labels to add to the startupapicheck's Service Account.


</td>
<td>object</td>
<td>

```yaml

```

</td>
</tr>
<tr>

<td>startupapicheck.volumes</td>
<td>

Additional volumes to add to the cert-manager controller pod.

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>startupapicheck.volumeMounts</td>
<td>

Additional volume mounts to add to the cert-manager controller container.

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>startupapicheck.enableServiceLinks</td>
<td>

enableServiceLinks indicates whether information about services should be injected into pod's environment variables, matching the syntax of Docker links.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
</table>

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
