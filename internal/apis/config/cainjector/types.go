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

package cainjector

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logsapi "k8s.io/component-base/logs/api/v1"

	shared "github.com/cert-manager/cert-manager/internal/apis/config/shared"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type CAInjectorConfiguration struct {
	metav1.TypeMeta

	// Paths to a kubeconfig. Only required if out-of-cluster.
	KubeConfig string

	// If set, this limits the scope of cert-manager to a single namespace and
	// ClusterIssuers are disabled. If not specified, all namespaces will be
	// watched"
	Namespace string

	// LeaderElectionConfig configures the behaviour of the leader election
	LeaderElectionConfig shared.LeaderElectionConfig

	// EnableDataSourceConfig determines whether cainjector's control loops will watch
	// cert-manager resources as potential sources of CA data.
	EnableDataSourceConfig EnableDataSourceConfig

	// EnableInjectableConfig determines whether cainjector's control loops will watch
	// cert-manager resources as potential targets for CA data injection.
	EnableInjectableConfig EnableInjectableConfig

	// Enable profiling for cainjector.
	EnablePprof bool

	// The host and port that Go profiler should listen on, i.e localhost:6060.
	// Ensure that profiler is not exposed on a public address. Profiler will be
	// served at /debug/pprof.
	PprofAddress string

	// https://pkg.go.dev/k8s.io/component-base@v0.27.3/logs/api/v1#LoggingConfiguration
	Logging logsapi.LoggingConfiguration

	// featureGates is a map of feature names to bools that enable or disable experimental
	// features.
	FeatureGates map[string]bool
}

type EnableDataSourceConfig struct {
	// Certificates detemines whether cainjector's control loops will watch
	// cert-manager Certificate resources as potential sources of CA data.
	Certificates bool
}

type EnableInjectableConfig struct {
	// ValidatingWebhookConfigurations determines whether cainjector
	// will spin up a control loop to inject CA data to annotated
	// ValidatingWebhookConfigurations
	ValidatingWebhookConfigurations bool

	// MutatingWebhookConfigurations determines whether cainjector
	// will spin up a control loop to inject CA data to annotated
	// MutatingWebhookConfigurations
	MutatingWebhookConfigurations bool

	// CustomResourceDefinitions determines whether cainjector
	// will spin up a control loop to inject CA data to annotated
	// CustomResourceDefinitions
	CustomResourceDefinitions bool

	// APIServices determines whether cainjector
	// will spin up a control loop to inject CA data to annotated
	// APIServices
	APIServices bool
}
