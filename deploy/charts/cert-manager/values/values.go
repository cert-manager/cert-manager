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

type HelmValues struct {
	Global Global `json:"global"`

	// If true, CRD resources will be installed as part of the Helm chart.
	// If enabled, when uninstalling CRD resources will be deleted causing all
	// installed custom resources to be DELETED
	InstallCRDs bool `json:"installCRDs"`

	Deployment `json:",inline"`

	CaInjector CaInjector `json:"cainjector"`
	Prometheus Prometheus `json:"prometheus"`
	Webhook    Webhook    `json:"webhook"`
	// This startupapicheck is a Helm post-install hook that waits for the webhook
	// endpoints to become available.
	// The check is implemented using a Kubernetes Job- if you are injecting mesh
	// sidecar proxies into cert-manager pods, you probably want to ensure that they
	// are not injected into this Job's pod. Otherwise the installation may time out
	// due to the Job never being completed because the sidecar proxy does not exit.
	// See https://github.com/jetstack/cert-manager/pull/4414 for context.
	StartupApiCheck StartupApiCheck `json:"startupapicheck"`

	// This namespace allows you to define where the services will be installed into
	// if not set then they will use the namespace of the release
	// This is helpful when installing cert manager as a chart dependency (sub chart)
	Namespace string `json:"namespace,omitempty"`

	// Override the namespace used to store DNS provider credentials etc. for ClusterIssuer
	// resources
	ClusterResourceNamespace string `json:"clusterResourceNamespace,omitempty"`

	// Comma-separated list of feature gates to enable on the controller pod
	FeatureGates string `json:"featureGates,omitempty"`

	// Value of the `HTTP_PROXY` environment variable in the cert-manager pod
	HttpProxy string `json:"http_proxy,omitempty"`
	// Value of the `HTTPS_PROXY` environment variable in the cert-manager pod
	HttpsProxy string `json:"https_proxy,omitempty"`
	// Value of the `NO_PROXY` environment variable in the cert-manager pod
	NoProxy string `json:"no_proxy,omitempty"`

	IngressShim IngressShim `json:"ingressShim"`

	// Optional cert-manager pod [DNS configurations](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pods-dns-config)
	PodDnsConfig interface{} `json:"podDnsConfig,omitempty"`

	// Optional cert-manager pod [DNS policy](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pods-dns-policy)
	PodDnsPolicy string `json:"podDnsPolicy,omitempty"`

	// Labels to add to the cert-manager controller service
	ServiceLabels map[string]string `json:"serviceLabels,omitempty"`

	// Volume mounts to add to cert-manager
	VolumeMounts []interface{} `json:"volumeMounts,omitempty"`

	// Volumes to add to cert-manager
	Volumes []interface{} `json:"volumes,omitempty"`

	// Annotations to add to the prometheus service
	ServiceAnnotations map[string]string `json:"serviceAnnotations,omitempty"`

	// (INTERNAL) Used to determine whether the helm.sh/chart label will be added to the rendered templates.
	// Set to static when building static manifests so that the helm.sh labels
	// will be omitted from the output.
	Creator string `json:"creator,omitempty" jsonschema:"enum=static,enum=helm"`
}
