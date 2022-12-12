/*
Copyright 2022 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package values

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Global struct {
	// Reference to one or more secrets to be used when pulling images
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`

	// Labels to apply to all resources
	// Please note that this does not add labels to the resources created dynamically by the controllers.
	// For these resources, you have to add the labels in the template in the cert-manager custom resource:
	// eg. podTemplate/ ingressTemplate in ACMEChallengeSolverHTTP01Ingress
	//    ref: https://cert-manager.io/docs/reference/api-docs/#acme.cert-manager.io/v1.ACMEChallengeSolverHTTP01Ingress
	// eg. secretTemplate in CertificateSpec
	//    ref: https://cert-manager.io/docs/reference/api-docs/#cert-manager.io/v1.CertificateSpec
	// +optional
	CommonLabels map[string]string `json:"commonLabels,omitempty"`

	// Priority class name for cert-manager and webhook pods
	PriorityClassName string `json:"priorityClassName,omitempty"`

	GlobalRbac GlobalRbac `json:"rbac"`

	PodSecurityPolicy PodSecurityPolicy `json:"podSecurityPolicy"`

	// Set the verbosity of cert-manager.
	// Range of 0 - 6 with 6 being the most verbose
	LogLevel int `json:"logLevel"`

	LeaderElection LeaderElection `json:"leaderElection"`
}

type GlobalRbac struct {
	// If `true`, create and use RBAC resources (includes sub-charts)
	Create bool `json:"create"`

	// Aggregate ClusterRoles to Kubernetes default user-facing roles.
	// Ref: https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles
	AggregateClusterRoles bool `json:"aggregateClusterRoles"`
}

type PodSecurityPolicy struct {
	// If `true`, create and use PodSecurityPolicy (includes sub-charts)
	Enabled bool `json:"enabled"`

	// If `true`, use Apparmor seccomp profile in PSP
	UseAppArmor bool `json:"useAppArmor"`
}

type LeaderElection struct {
	// Override the namespace used to store the ConfigMap for leader election
	Namespace string `json:"namespace"`

	// The duration that non-leader candidates will wait after observing a
	// leadership renewal until attempting to acquire leadership of a led but
	// unrenewed leader slot. This is effectively the maximum duration that a
	// leader can be stopped before it is replaced by another candidate
	LeaseDuration metav1.Duration `json:"leaseDuration,omitempty"`

	// The interval between attempts by the acting master to renew a leadership
	// slot before it stops leading. This must be less than or equal to the
	// lease duration
	RenewDeadline metav1.Duration `json:"renewDeadline,omitempty"`

	// The duration the clients should wait between attempting acquisition and
	// renewal of a leadership
	RetryPeriod metav1.Duration `json:"retryPeriod,omitempty"`
}
