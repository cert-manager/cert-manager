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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logsapi "k8s.io/component-base/logs/api/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type CAInjectorConfiguration struct {
	metav1.TypeMeta `json:",inline"`

	// kubeConfig is the kubeconfig file used to connect to the Kubernetes apiserver.
	// If not specified, the cainjector will attempt to load the in-cluster-config.
	KubeConfig string `json:"kubeConfig,omitempty"`

	// If set, this limits the scope of cainjector to a single namespace.
	// If set, cainjector will not update resources with certificates outside of the
	// configured namespace.
	Namespace string `json:"namespace,omitempty"`

	// LeaderElectionConfig configures the behaviour of the leader election
	LeaderElectionConfig LeaderElectionConfig `json:"leaderElectionConfig"`

	// EnableDataSourceConfig determines whether cainjector's control loops will watch
	// cert-manager resources as potential sources of CA data.
	EnableDataSourceConfig EnableDataSourceConfig `json:"enableDataSourceConfig"`

	// EnableInjectableConfig determines whether cainjector's control loops will watch
	// cert-manager resources as potential targets for CA data injection.
	EnableInjectableConfig EnableInjectableConfig `json:"enableInjectableConfig"`

	// Enable profiling for cainjector.
	EnablePprof bool `json:"enablePprof"`

	// The host and port that Go profiler should listen on, i.e localhost:6060.
	// Ensure that profiler is not exposed on a public address. Profiler will be
	// served at /debug/pprof.
	PprofAddress string `json:"pprofAddress,omitempty"`

	// logging configures the logging behaviour of the cainjector.
	// https://pkg.go.dev/k8s.io/component-base@v0.27.3/logs/api/v1#LoggingConfiguration
	Logging logsapi.LoggingConfiguration `json:"logging"`

	// featureGates is a map of feature names to bools that enable or disable experimental
	// features.
	// +optional
	FeatureGates map[string]bool `json:"featureGates,omitempty"`
}

type LeaderElectionConfig struct {
	// If true, cert-manager will perform leader election between instances to
	// ensure no more than one instance of cert-manager operates at a time
	Enabled *bool `json:"enabled,omitempty"`

	// Namespace used to perform leader election. Only used if leader election is enabled
	Namespace string `json:"namespace,omitempty"`

	// The duration that non-leader candidates will wait after observing a leadership
	// renewal until attempting to acquire leadership of a led but unrenewed leader
	// slot. This is effectively the maximum duration that a leader can be stopped
	// before it is replaced by another candidate. This is only applicable if leader
	// election is enabled.
	LeaseDuration time.Duration `json:"leaseDuration,omitempty"`

	// The interval between attempts by the acting master to renew a leadership slot
	// before it stops leading. This must be less than or equal to the lease duration.
	// This is only applicable if leader election is enabled.
	RenewDeadline time.Duration `json:"renewDeadline,omitempty"`

	// The duration the clients should wait between attempting acquisition and renewal
	// of a leadership. This is only applicable if leader election is enabled.
	RetryPeriod time.Duration `json:"retryPeriod,omitempty"`
}

type EnableDataSourceConfig struct {
	// Certificates detemines whether cainjector's control loops will watch
	// cert-manager Certificate resources as potential sources of CA data.
	// If not set, defaults to true.
	Certificates *bool `json:"certificates"`
}

type EnableInjectableConfig struct {
	// ValidatingWebhookConfigurations determines whether cainjector
	// will spin up a control loop to inject CA data to annotated
	// ValidatingWebhookConfigurations
	// If not set, defaults to true.
	ValidatingWebhookConfigurations *bool `json:"validatingWebhookConfigurations"`

	// MutatingWebhookConfigurations determines whether cainjector
	// will spin up a control loop to inject CA data to annotated
	// MutatingWebhookConfigurations
	// If not set, defaults to true.
	MutatingWebhookConfigurations *bool `json:"mutatingWebhookConfigurations"`

	// CustomResourceDefinitions determines whether cainjector
	// will spin up a control loop to inject CA data to annotated
	// CustomResourceDefinitions
	// If not set, defaults to true.
	CustomResourceDefinitions *bool `json:"customResourceDefinitions"`

	// APIServices determines whether cainjector
	// will spin up a control loop to inject CA data to annotated
	// APIServices
	// If not set, defaults to true.
	APIServices *bool `json:"apiServices"`
}
