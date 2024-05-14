/*
Copyright 2021 The cert-manager Authors.

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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logsapi "k8s.io/component-base/logs/api/v1"

	sharedv1alpha1 "github.com/cert-manager/cert-manager/pkg/apis/config/shared/v1alpha1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type WebhookConfiguration struct {
	metav1.TypeMeta `json:",inline"`

	// securePort is the port number to listen on for secure TLS connections from the kube-apiserver.
	// If 0, a random available port will be chosen.
	// Defaults to 6443.
	SecurePort *int32 `json:"securePort,omitempty"`

	// healthzPort is the port number to listen on (using plaintext HTTP) for healthz connections.
	// If 0, a random available port will be chosen.
	// Defaults to 6080.
	HealthzPort *int32 `json:"healthzPort,omitempty"`

	// tlsConfig is used to configure the secure listener's TLS settings.
	TLSConfig sharedv1alpha1.TLSConfig `json:"tlsConfig"`

	// kubeConfig is the kubeconfig file used to connect to the Kubernetes apiserver.
	// If not specified, the webhook will attempt to load the in-cluster-config.
	KubeConfig string `json:"kubeConfig,omitempty"`

	// apiServerHost is used to override the API server connection address.
	// Deprecated: use `kubeConfig` instead.
	APIServerHost string `json:"apiServerHost,omitempty"`

	// enablePprof configures whether pprof is enabled.
	EnablePprof bool `json:"enablePprof"`

	// pprofAddress configures the address on which /debug/pprof endpoint will be served if enabled.
	// Defaults to 'localhost:6060'.
	PprofAddress string `json:"pprofAddress,omitempty"`

	// logging configures the logging behaviour of the webhook.
	// https://pkg.go.dev/k8s.io/component-base@v0.27.3/logs/api/v1#LoggingConfiguration
	Logging logsapi.LoggingConfiguration `json:"logging"`

	// featureGates is a map of feature names to bools that enable or disable experimental
	// features.
	// +optional
	FeatureGates map[string]bool `json:"featureGates,omitempty"`
}
