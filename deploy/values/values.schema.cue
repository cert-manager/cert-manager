package schema

import (
	corev1 "k8s.io/api/core/v1"
	appsv1 "k8s.io/api/apps/v1"
)

#Image: {
	// Image repository
	repository: string

	// You can manage a registry with
	// Example:
	// registry: quay.io
	// repository: jetstack/cert-manager-controller
	registry?: string

	// Image tag
	tag?: string

	// Setting a digest will override any tag
	digest?: string

	// Image pull policy
	pullPolicy?: string
}

#ServiceAccount: {
	// If `true`, create a new service account
	create: bool

	// Service account to be used.
	// If not set and `serviceAccount.create` is `true`, a name is
	// generated using
	// the fullname template
	name?: string

	// Optional additional labels to add to the controller's ServiceAccount
	labels?: {[string]: string}

	// Annotations to add to the service account for the cert-manager
	// controller
	annotations?: {[string]: string}

	// Automount API credentials for the cert-manager service account
	automountServiceAccountToken: bool
}

#PodFields: {
	// Annotations to add to the pods
	podAnnotations?: {[string]: string}

	// Annotations to add to the pods
	podLabels?: {[string]: string}

	// Node labels for pod assignment
	nodeSelector?: {[string]: string}

	// Node affinity for pod assignment
	affinity?: corev1.#Affinity

	// Node tolerations for pod assignment
	tolerations?: [...string]

	image: #Image

	// CPU/memory resource requests/limits
	resources?: corev1.#ResourceRequirements

	// Optional additional arguments for pod
	extraArgs?: [...string]

	// Optional additional environment variables for pod
	extraEnv?: [...corev1.#EnvVar]

	// Service account configuration for pod
	serviceAccount?: #ServiceAccount

	// Pod Security Context
	// ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
	securityContext?: corev1.#PodSecurityContext

	// Container Security Context to be set on the controller
	// component container
	// ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
	containerSecurityContext?: corev1.#SecurityContext
}

#DeploymentFields: {
	#PodFields

	// Number of replicas
	replicaCount: int

	// Annotations to add to the deployment
	deploymentAnnotations?: {[string]: string}

	// Deployment strategy
	strategy?: appsv1.#DeploymentStrategy
}

#Values: {
	// If true, CRD resources will be installed as part of the Helm
	// chart. If enabled, when uninstalling CRD resources will be deleted
	// causing all installed custom resources to be DELETED
	installCRDs: bool

	// This namespace allows you to define where the services will be installed into
	// if not set then they will use the namespace of the release
	// This is helpful when installing cert manager as a chart dependency (sub chart)
	namespace: string

	// Automounting API credentials for a particular pod
	automountServiceAccountToken?: bool

	#DeploymentFields

	// Volumes to add to cert-manager
	volumes?: [...corev1.#Volume]

	// Volume mounts to add to cert-manager
	volumeMounts?: [...corev1.#VolumeMount]

	// Override the namespace used to store DNS provider credentials
	// etc. for ClusterIssuer resources
	clusterResourceNamespace?: string

	// Comma-separated list of feature gates to enable on the
	// controller pod
	featureGates?: string

	// Value of the `HTTP_PROXY` environment variable in the
	// cert-manager pod
	http_proxy?: string

	// Value of the `HTTPS_PROXY` environment variable in the
	// cert-manager pod
	https_proxy?: string

	// Value of the `NO_PROXY` environment variable in the
	// cert-manager pod
	no_proxy?: string

	ingressShim: {
		// Optional default issuer group to use for ingress resources
		defaultIssuerGroup?: string

		// Optional default issuer kind to use for ingress resources
		defaultIssuerKind?: string

		// Optional default issuer to use for ingress resources
		defaultIssuerName?: string
	}

	// Optional cert-manager pod [DNS configurations](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pods-dns-config)
	podDnsConfig?: corev1.#PodDNSConfig

	// Optional cert-manager pod [DNS policy](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pods-dns-policy)
	podDnsPolicy?: corev1.#DNSPolicy

	// Labels to add to the cert-manager controller service
	serviceLabels?: {[string]: string}

	// (INTERNAL) Used to determine whether the helm.sh/chart label
	// will be added to the rendered templates.
	// Set to static when building static manifests so that the
	// helm.sh labels
	// will be omitted from the output.
	creator?: "static" | "helm"

	global: {
		// Set the verbosity of cert-manager. Range of 0 - 6 with 6 being
		// the most verbose
		logLevel: int

		// Priority class name for cert-manager and webhook pods
		priorityClassName?: string

		// Reference to one or more secrets to be used when pulling images
		imagePullSecrets?: [...corev1.#LocalObjectReference]

		leaderElection: {
			// Override the namespace used to store the ConfigMap for leader
			// election
			namespace: string

			// The duration that non-leader candidates will wait after
			// observing a
			// leadership renewal until attempting to acquire leadership of a
			// led but
			// unrenewed leader slot. This is effectively the maximum duration
			// that a
			// leader can be stopped before it is replaced by another
			// candidate
			leaseDuration?: string

			// The interval between attempts by the acting master to renew a
			// leadership
			// slot before it stops leading. This must be less than or equal
			// to the
			// lease duration
			renewDeadline?: string

			// The duration the clients should wait between attempting
			// acquisition and
			// renewal of a leadership
			retryPeriod?: string
		}

		podSecurityPolicy: {
			// If `true`, create and use PodSecurityPolicy (includes
			// sub-charts)
			enabled: bool

			// If `true`, use Apparmor seccomp profile in PSP
			useAppArmor: bool
		}

		rbac: {
			// If `true`, create and use RBAC resources (includes sub-charts)
			create: bool

			// Aggregate ClusterRoles to Kubernetes default user-facing roles.
			// Ref: https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles
			aggregateClusterRoles: bool
		}
	}

	prometheus: {
		// Enable Prometheus monitoring
		enabled: bool

		servicemonitor: {
			// Enable Prometheus Operator ServiceMonitor monitoring
			enabled: bool

			// Define namespace where to deploy the ServiceMonitor resource
			namespace?: string

			// Prometheus Instance definition
			prometheusInstance: string

			// Prometheus scrape port
			targetPort: int

			// Prometheus scrape path
			path: string

			// Prometheus scrape interval
			interval: string

			// Prometheus scrape timeout
			scrapeTimeout: string

			// Add custom labels to ServiceMonitor
			labels?: {[string]: string}

			// Should honor labels
			honorLabels: bool
		}
	}

	cainjector: {
		// Toggles whether the cainjector component should be installed
		// (required for the webhook component to work)
		enabled: bool

		#DeploymentFields
	}

	// This startupapicheck is a Helm post-install hook that waits for
	// the webhook endpoints to become available. The check is implemented
	// using a Kubernetes Job- if you are injecting mesh sidecar proxies
	// into cert-manager pods, you probably want to ensure that they
	// are not injected into this Job's pod. Otherwise the installation
	// may time out due to the Job never being completed because the sidecar
	// proxy does not exit.
	// See https://github.com/jetstack/cert-manager/pull/4414 for context.
	startupapicheck: {
		// Toggles whether the startupapicheck Job should be installed
		enabled: bool

		#PodFields

		// Timeout for 'kubectl check api' command
		timeout: string

		// Job backoffLimit
		backoffLimit: int

		// Annotations to add to the Job
		jobAnnotations?: {[string]: string}

		rbac: {
			// Annotations to add to the rbac resources
			annotations?: {[string]: string}
		}
	}

	webhook: {
		// Used to configure options for the webhook pod.
		// This allows setting options that'd usually be provided via flags.
		// An APIVersion and Kind must be specified in your values.yaml file.
		// Flags will override options that are set here.
		config: {
			apiVersion?: string
			kind?:       string

			// The port that the webhook should listen on for requests.
			// In GKE private clusters, by default kubernetes apiservers are allowed to
			// talk to the cluster nodes only on 443 and 10250. so configuring
			// securePort: 10250, will work out of the box without needing to add firewall
			// rules or requiring NET_BIND_SERVICE capabilities to bind port numbers <1000.
			// This should be uncommented and set as a default by the chart once we graduate
			// the apiVersion of WebhookConfiguration past v1alpha1.
			securePort?: int
		}

		#DeploymentFields

		// The webhook liveness probe
		livenessProbe: corev1.#Probe

		// The webhook readiness probe
		readinessProbe: corev1.#Probe

		// The port that the webhook should listen on for requests.
		securePort: int

		// If `true`, run the Webhook on the host network.
		hostNetwork: bool

		// The type of the `Service`.
		serviceType: string

		// The specific load balancer IP to use (when `serviceType` is `LoadBalancer`).
		loadBalancerIP?: string

		// Labels to add to the cert-manager webhook service
		serviceLabels?: {[string]: string}

		// Annotations to add to the cert-manager webhook service
		serviceAnnotations?: {[string]: string}

		// Seconds the API server should wait the webhook to respond
		// before treating the call as a failure.
		timeoutSeconds: int

		// Overrides the mutating webhook and validating webhook so they
		// reach the webhook
		// service using the `url` field instead of a service.
		url: {
			// The host to use to reach the webhook, instead of using internal
			// cluster DNS for the service.
			host?: string
		}

		// Annotations to add to the webhook MutatingWebhookConfiguration
		mutatingWebhookConfigurationAnnotations?: {[string]: string}

		// Annotations to add to the webhook
		// ValidatingWebhookConfiguration
		validatingWebhookConfigurationAnnotations?: {[string]: string}
	}
}
