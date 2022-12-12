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

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type Prometheus struct {
	// Enable Prometheus monitoring
	Enabled bool `json:"enabled"`

	Servicemonitor Servicemonitor `json:"servicemonitor"`
}

type Servicemonitor struct {
	// Enable Prometheus Operator ServiceMonitor monitoring
	Enabled bool `json:"enabled"`

	// Define namespace where to deploy the ServiceMonitor resource
	Namespace string `json:"namespace,omitempty"`

	// Prometheus Instance definition
	PrometheusInstance string `json:"prometheusInstance"`

	//Prometheus scrape port
	TargetPort int `json:"targetPort"`

	// Prometheus scrape path
	Path string `json:"path"`

	// Prometheus scrape interval
	Interval metav1.Duration `json:"interval"`

	// Prometheus scrape timeout
	ScrapeTimeout metav1.Duration `json:"scrapeTimeout"`

	// Add custom labels to ServiceMonitor
	Labels map[string]string `json:"labels,omitempty"`

	HonorLabels bool `json:"honorLabels,omitempty"`

	Annotations map[string]string `json:"annotations,omitempty"`
}
