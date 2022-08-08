package values

import "private-package.io:schema"

schema.#Values

installCRDs: false
namespace:   ""
ingressShim: {}
replicaCount: 1
securityContext: {
	runAsNonRoot: true
	seccompProfile: type: "RuntimeDefault"
}
containerSecurityContext: {
	allowPrivilegeEscalation: false
	capabilities: drop: ["ALL"]
}
serviceAccount: {
	automountServiceAccountToken: true
	create:                       true
}
image: {
	pullPolicy: "IfNotPresent"
	repository: "quay.io/jetstack/cert-manager-controller"
}
nodeSelector: "kubernetes.io/os": "linux"

prometheus: {
	enabled: true
	servicemonitor: {
		enabled:            false
		interval:           "60s"
		path:               "/metrics"
		prometheusInstance: "default"
		scrapeTimeout:      "30s"
		targetPort:         9402
		honorLabels:        false
	}
}

global: {
	leaderElection: namespace: "kube-system"
	logLevel: 2
	podSecurityPolicy: {
		enabled:     false
		useAppArmor: true
	}
	rbac: {
		create:                true
		aggregateClusterRoles: true
	}
}

cainjector: {
	enabled: true

	replicaCount: 1
	securityContext: {
		runAsNonRoot: true
		seccompProfile: type: "RuntimeDefault"
	}
	containerSecurityContext: {
		allowPrivilegeEscalation: false
		capabilities: drop: ["ALL"]
	}

	image: {
		pullPolicy: "IfNotPresent"
		repository: "quay.io/jetstack/cert-manager-cainjector"
	}
	nodeSelector: "kubernetes.io/os": "linux"

	serviceAccount: {
		automountServiceAccountToken: true
		create:                       true
	}
}

startupapicheck: {
	enabled: true

	backoffLimit: 4
	timeout:      "1m"

	securityContext: {
		runAsNonRoot: true
		seccompProfile: type: "RuntimeDefault"
	}
	containerSecurityContext: {
		allowPrivilegeEscalation: false
		capabilities: drop: ["ALL"]
	}

	image: {
		pullPolicy: "IfNotPresent"
		repository: "quay.io/jetstack/cert-manager-ctl"
	}
	nodeSelector: "kubernetes.io/os": "linux"

	jobAnnotations: {
		"helm.sh/hook":               "post-install"
		"helm.sh/hook-delete-policy": "before-hook-creation,hook-succeeded"
		"helm.sh/hook-weight":        "1"
	}
	rbac: annotations: {
		"helm.sh/hook":               "post-install"
		"helm.sh/hook-delete-policy": "before-hook-creation,hook-succeeded"
		"helm.sh/hook-weight":        "-5"
	}
	serviceAccount: {
		annotations: {
			"helm.sh/hook":               "post-install"
			"helm.sh/hook-delete-policy": "before-hook-creation,hook-succeeded"
			"helm.sh/hook-weight":        "-5"
		}
		automountServiceAccountToken: true
		create:                       true
	}
}

webhook: {
	hostNetwork: false

	image: {
		pullPolicy: "IfNotPresent"
		repository: "quay.io/jetstack/cert-manager-webhook"
	}
	nodeSelector: "kubernetes.io/os": "linux"

	livenessProbe: {
		failureThreshold:    3
		initialDelaySeconds: 60
		periodSeconds:       10
		successThreshold:    1
		timeoutSeconds:      1
	}
	readinessProbe: {
		failureThreshold:    3
		initialDelaySeconds: 5
		periodSeconds:       5
		successThreshold:    1
		timeoutSeconds:      1
	}
	replicaCount: 1
	securePort:   10250
	securityContext: {
		runAsNonRoot: true
		seccompProfile: type: "RuntimeDefault"
	}
	containerSecurityContext: {
		allowPrivilegeEscalation: false
		capabilities: drop: ["ALL"]
	}
	serviceAccount: {
		automountServiceAccountToken: true
		create:                       true
	}
	serviceType:    "ClusterIP"
	timeoutSeconds: 10
	url: {}
}
