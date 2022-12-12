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
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type WebhookUrl struct {
	// The host to use to reach the webhook, instead of using internal cluster DNS for the service.
	Host string `json:"host,omitempty"`
}

type Webhook struct {
	Deployment `json:",inline"`

	LivenessProbe  Probe `json:"livenessProbe"`
	ReadinessProbe Probe `json:"readinessProbe"`

	// The port that the webhook should listen on for requests.
	SecurePort int `json:"securePort"`

	// If `true`, run the Webhook on the host network.
	HostNetwork bool `json:"hostNetwork"`

	// The type of the `Service`.
	ServiceType corev1.ServiceType `json:"serviceType"`

	// The specific load balancer IP to use (when `serviceType` is `LoadBalancer`).
	LoadBalancerIP string `json:"loadBalancerIP,omitempty"`

	// Labels to add to the cert-manager webhook service
	ServiceLabels map[string]string `json:"serviceLabels,omitempty"`

	// Annotations to add to the cert-manager webhook service
	ServiceAnnotations map[string]string `json:"serviceAnnotations,omitempty"`

	// Seconds the API server should wait the webhook to respond before treating the call as a failure.
	TimeoutSeconds int `json:"timeoutSeconds"`

	// Overrides the mutating webhook and validating webhook so they reach the webhook
	// service using the `url` field instead of a service.
	Url WebhookUrl `json:"url"`

	// Annotations to add to the webhook MutatingWebhookConfiguration
	MutatingWebhookConfigurationAnnotations map[string]string `json:"mutatingWebhookConfigurationAnnotations,omitempty"`

	// Annotations to add to the webhook ValidatingWebhookConfiguration
	ValidatingWebhookConfigurationAnnotations map[string]string `json:"validatingWebhookConfigurationAnnotations,omitempty"`

	// NetworkPolicy
	NetworkPolicy NetworkPolicy `json:"networkPolicy"`

	// Used to configure options for the webhook pod.
	// This allows setting options that'd usually be provided via flags.
	// An APIVersion and Kind must be specified in your values.yaml file.
	// Flags will override options that are set here.
	// +optional
	Config WebhookConfig `json:"config,omitempty"`
}

type NetworkPolicy struct {
	// Toggles whether the NetworkPolicies should be installed
	Enabled bool `json:"enabled"`

	Ingress []networkingv1.NetworkPolicyIngressRule `json:"ingress"`

	Egress []networkingv1.NetworkPolicyEgressRule `json:"egress"`
}

type WebhookConfig struct {
	metav1.TypeMeta `json:",inline"`

	// The port that the webhook should listen on for requests.
	// In GKE private clusters, by default kubernetes apiservers are allowed to
	// talk to the cluster nodes only on 443 and 10250. so configuring
	// securePort: 10250, will work out of the box without needing to add firewall
	// rules or requiring NET_BIND_SERVICE capabilities to bind port numbers <1000.
	// This should be uncommented and set as a default by the chart once we graduate
	// the apiVersion of WebhookConfiguration past v1alpha1.
	SecurePort int `json:"securePort"`
}
