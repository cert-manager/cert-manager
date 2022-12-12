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
)

type Pod struct {
	// Annotations to add to the pods
	PodAnnotations map[string]string `json:"podAnnotations,omitempty"`

	// Annotations to add to the pods
	PodLabels map[string]string `json:"podLabels,omitempty"`

	// Node labels for pod assignment
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Node affinity for pod assignment
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// Node tolerations for pod assignment
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	Image Image `json:"image"`

	// CPU/memory resource requests/limits
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// Optional additional arguments for pod
	ExtraArgs []string `json:"extraArgs,omitempty"`

	// Optional additional environment variables for pod
	ExtraEnv []corev1.EnvVar `json:"extraEnv,omitempty"`

	// Service account configuration for pod
	ServiceAccount ServiceAccount `json:"serviceAccount"`

	// AutomountServiceAccountToken indicates whether pods running as this service account should have an API token automatically mounted.
	// Can be overridden at the pod level.
	// +optional
	AutomountServiceAccountToken *bool `json:"automountServiceAccountToken,omitempty"`

	// Pod Security Context
	// ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
	// +optional
	SecurityContext *corev1.PodSecurityContext `json:"securityContext"`

	// Container Security Context to be set on the controller component container
	// ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
	// +optional
	ContainerSecurityContext *corev1.SecurityContext `json:"containerSecurityContext,omitempty"`

	// TopologySpreadConstraints describes how a group of pods ought to spread across topology
	// domains. Scheduler will schedule pods in a way which abides by the constraints.
	// All topologySpreadConstraints are ANDed.
	// +optional
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
}
