/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package v1alpha3

import (
	corev1 "k8s.io/api/core/v1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"

	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
)

// ACMEIssuer contains the specification for an ACME issuer
type ACMEIssuer struct {
	// Email is the email for this account
	// +optional
	Email string `json:"email,omitempty"`

	// Server is the ACME server URL
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Server string `json:"server"`

	// If true, skip verifying the ACME server TLS certificate
	// +optional
	SkipTLSVerify bool `json:"skipTLSVerify,omitempty"`

	// ExternalAccountBinding is a reference to a CA external account of the ACME
	// server.
	// +optional
	ExternalAccountBinding *ACMEExternalAccountBinding `json:"externalAccountBinding,omitempty"`

	// PrivateKey is the name of a secret containing the private key for this
	// user account.
	PrivateKey cmmeta.SecretKeySelector `json:"privateKeySecretRef"`

	// Solvers is a list of challenge solvers that will be used to solve
	// ACME challenges for the matching domains.
	Solvers []ACMEChallengeSolver `json:"solvers,omitempty"`
}

// ACMEExternalAccountBinding is a reference to a CA external account of the ACME
// server.
type ACMEExternalAccountBinding struct {
	// keyID is the ID of the CA key that the External Account is bound to.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	KeyID string `json:"keyID"`

	// keySecretRef is a Secret Key Selector referencing a data item in a Kubernetes
	// Secret which holds the symmetric MAC key of the External Account Binding.
	// The `key` is the index string that is paired with the key data in the
	// Secret and should not be confused with the key data itself, or indeed with
	// the External Account Binding keyID above.
	// The secret key stored in the Secret **must** be un-padded, base64 URL
	// encoded data.
	// +kubebuilder:validation:Required
	Key cmmeta.SecretKeySelector `json:"keySecretRef"`

	// keyAlgorithm is the MAC key algorithm that the key is used for. Valid
	// values are "HS256", "HS384" and "HS512".
	// +kubebuilder:validation:Required
	KeyAlgorithm HMACKeyAlgorithm `json:"keyAlgorithm"`
}

// HMACKeyAlgorithm is the name of a key algorithm used for HMAC encryption
// +kubebuilder:validation:Enum=HS256;HS384;HS512
type HMACKeyAlgorithm string

const (
	HS256 HMACKeyAlgorithm = "HS256"
	HS384 HMACKeyAlgorithm = "HS384"
	HS512 HMACKeyAlgorithm = "HS512"
)

type ACMEChallengeSolver struct {
	// Selector selects a set of DNSNames on the Certificate resource that
	// should be solved using this challenge solver.
	Selector *CertificateDNSNameSelector `json:"selector,omitempty"`

	// +optional
	HTTP01 *ACMEChallengeSolverHTTP01 `json:"http01,omitempty"`

	// +optional
	DNS01 *ACMEChallengeSolverDNS01 `json:"dns01,omitempty"`
}

// CertificateDomainSelector selects certificates using a label selector, and
// can optionally select individual DNS names within those certificates.
// If both MatchLabels and DNSNames are empty, this selector will match all
// certificates and DNS names within them.
type CertificateDNSNameSelector struct {
	// A label selector that is used to refine the set of certificate's that
	// this challenge solver will apply to.
	// +optional
	MatchLabels map[string]string `json:"matchLabels,omitempty"`

	// List of DNSNames that this solver will be used to solve.
	// If specified and a match is found, a dnsNames selector will take
	// precedence over a dnsZones selector.
	// If multiple solvers match with the same dnsNames value, the solver
	// with the most matching labels in matchLabels will be selected.
	// If neither has more matches, the solver defined earlier in the list
	// will be selected.
	// +optional
	DNSNames []string `json:"dnsNames,omitempty"`

	// List of DNSZones that this solver will be used to solve.
	// The most specific DNS zone match specified here will take precedence
	// over other DNS zone matches, so a solver specifying sys.example.com
	// will be selected over one specifying example.com for the domain
	// www.sys.example.com.
	// If multiple solvers match with the same dnsZones value, the solver
	// with the most matching labels in matchLabels will be selected.
	// If neither has more matches, the solver defined earlier in the list
	// will be selected.
	// +optional
	DNSZones []string `json:"dnsZones,omitempty"`
}

// ACMEChallengeSolverHTTP01 contains configuration detailing how to solve
// HTTP01 challenges within a Kubernetes cluster.
// Typically this is accomplished through creating 'routes' of some description
// that configure ingress controllers to direct traffic to 'solver pods', which
// are responsible for responding to the ACME server's HTTP requests.
type ACMEChallengeSolverHTTP01 struct {
	// The ingress based HTTP01 challenge solver will solve challenges by
	// creating or modifying Ingress resources in order to route requests for
	// '/.well-known/acme-challenge/XYZ' to 'challenge solver' pods that are
	// provisioned by cert-manager for each Challenge to be completed.
	// +optional
	Ingress *ACMEChallengeSolverHTTP01Ingress `json:"ingress"`
}

type ACMEChallengeSolverHTTP01Ingress struct {
	// Optional service type for Kubernetes solver service
	// +optional
	ServiceType corev1.ServiceType `json:"serviceType,omitempty"`

	// The ingress class to use when creating Ingress resources to solve ACME
	// challenges that use this challenge solver.
	// Only one of 'class' or 'name' may be specified.
	// +optional
	Class *string `json:"class,omitempty"`

	// The name of the ingress resource that should have ACME challenge solving
	// routes inserted into it in order to solve HTTP01 challenges.
	// This is typically used in conjunction with ingress controllers like
	// ingress-gce, which maintains a 1:1 mapping between external IPs and
	// ingress resources.
	// +optional
	Name string `json:"name,omitempty"`

	// Optional pod template used to configure the ACME challenge solver pods
	// used for HTTP01 challenges
	// +optional
	PodTemplate *ACMEChallengeSolverHTTP01IngressPodTemplate `json:"podTemplate,omitempty"`

	// Optional ingress template used to configure the ACME challenge solver
	// ingress used for HTTP01 challenges
	// +optional
	IngressTemplate *ACMEChallengeSolverHTTP01IngressTemplate `json:"ingressTemplate,omitempty"`
}

type ACMEChallengeSolverHTTP01IngressPodTemplate struct {
	// ObjectMeta overrides for the pod used to solve HTTP01 challenges.
	// Only the 'labels' and 'annotations' fields may be set.
	// If labels or annotations overlap with in-built values, the values here
	// will override the in-built values.
	// +optional
	ACMEChallengeSolverHTTP01IngressPodObjectMeta `json:"metadata"`

	// PodSpec defines overrides for the HTTP01 challenge solver pod.
	// Only the 'nodeSelector', 'affinity' and 'tolerations' fields are
	// supported currently. All other fields will be ignored.
	// +optional
	Spec ACMEChallengeSolverHTTP01IngressPodSpec `json:"spec"`
}

type ACMEChallengeSolverHTTP01IngressPodObjectMeta struct {
	// Annotations that should be added to the create ACME HTTP01 solver pods.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Labels that should be added to the created ACME HTTP01 solver pods.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
}

type ACMEChallengeSolverHTTP01IngressPodSpec struct {
	// NodeSelector is a selector which must be true for the pod to fit on a node.
	// Selector which must match a node's labels for the pod to be scheduled on that node.
	// More info: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// If specified, the pod's scheduling constraints
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// If specified, the pod's tolerations.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

type ACMEChallengeSolverHTTP01IngressTemplate struct {
	// ObjectMeta overrides for the ingress used to solve HTTP01 challenges.
	// Only the 'labels' and 'annotations' fields may be set.
	// If labels or annotations overlap with in-built values, the values here
	// will override the in-built values.
	// +optional
	ACMEChallengeSolverHTTP01IngressObjectMeta `json:"metadata"`
}

type ACMEChallengeSolverHTTP01IngressObjectMeta struct {
	// Annotations that should be added to the created ACME HTTP01 solver ingress.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Labels that should be added to the created ACME HTTP01 solver ingress.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
}

type ACMEChallengeSolverDNS01 struct {
	// CNAMEStrategy configures how the DNS01 provider should handle CNAME
	// records when found in DNS zones.
	// +optional
	CNAMEStrategy CNAMEStrategy `json:"cnameStrategy,omitempty"`

	// +optional
	Akamai *ACMEIssuerDNS01ProviderAkamai `json:"akamai,omitempty"`

	// +optional
	CloudDNS *ACMEIssuerDNS01ProviderCloudDNS `json:"clouddns,omitempty"`

	// +optional
	Cloudflare *ACMEIssuerDNS01ProviderCloudflare `json:"cloudflare,omitempty"`

	// +optional
	Route53 *ACMEIssuerDNS01ProviderRoute53 `json:"route53,omitempty"`

	// +optional
	AzureDNS *ACMEIssuerDNS01ProviderAzureDNS `json:"azuredns,omitempty"`

	// +optional
	DigitalOcean *ACMEIssuerDNS01ProviderDigitalOcean `json:"digitalocean,omitempty"`

	// +optional
	AcmeDNS *ACMEIssuerDNS01ProviderAcmeDNS `json:"acmedns,omitempty"`

	// +optional
	RFC2136 *ACMEIssuerDNS01ProviderRFC2136 `json:"rfc2136,omitempty"`

	// +optional
	Webhook *ACMEIssuerDNS01ProviderWebhook `json:"webhook,omitempty"`
}

// CNAMEStrategy configures how the DNS01 provider should handle CNAME records
// when found in DNS zones.
// By default, the None strategy will be applied (i.e. do not follow CNAMEs).
// +kubebuilder:validation:Enum=None;Follow
type CNAMEStrategy string

const (
	// NoneStrategy indicates that no CNAME resolution strategy should be used
	// when determining which DNS zone to update during DNS01 challenges.
	NoneStrategy = "None"

	// FollowStrategy will cause cert-manager to recurse through CNAMEs in
	// order to determine which DNS zone to update during DNS01 challenges.
	// This is useful if you do not want to grant cert-manager access to your
	// root DNS zone, and instead delegate the _acme-challenge.example.com
	// subdomain to some other, less privileged domain.
	FollowStrategy = "Follow"
)

// ACMEIssuerDNS01ProviderAkamai is a structure containing the DNS
// configuration for Akamai DNS—Zone Record Management API
type ACMEIssuerDNS01ProviderAkamai struct {
	ServiceConsumerDomain string                   `json:"serviceConsumerDomain"`
	ClientToken           cmmeta.SecretKeySelector `json:"clientTokenSecretRef"`
	ClientSecret          cmmeta.SecretKeySelector `json:"clientSecretSecretRef"`
	AccessToken           cmmeta.SecretKeySelector `json:"accessTokenSecretRef"`
}

// ACMEIssuerDNS01ProviderCloudDNS is a structure containing the DNS
// configuration for Google Cloud DNS
type ACMEIssuerDNS01ProviderCloudDNS struct {
	// +optional
	ServiceAccount *cmmeta.SecretKeySelector `json:"serviceAccountSecretRef,omitempty"`

	// +kubebuilder:validation:MinLength=1
	Project string `json:"project"`
}

// ACMEIssuerDNS01ProviderCloudflare is a structure containing the DNS
// configuration for Cloudflare
type ACMEIssuerDNS01ProviderCloudflare struct {
	Email string `json:"email"`

	// +optional
	APIKey *cmmeta.SecretKeySelector `json:"apiKeySecretRef,omitempty"`

	// + optional
	APIToken *cmmeta.SecretKeySelector `json:"apiTokenSecretRef,omitempty"`
}

// ACMEIssuerDNS01ProviderDigitalOcean is a structure containing the DNS
// configuration for DigitalOcean Domains
type ACMEIssuerDNS01ProviderDigitalOcean struct {
	Token cmmeta.SecretKeySelector `json:"tokenSecretRef"`
}

// ACMEIssuerDNS01ProviderRoute53 is a structure containing the Route 53
// configuration for AWS
type ACMEIssuerDNS01ProviderRoute53 struct {
	// The AccessKeyID is used for authentication. If not set we fall-back to using env vars, shared credentials file or AWS Instance metadata
	// see: https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials
	// +optional
	AccessKeyID string `json:"accessKeyID"`

	// The SecretAccessKey is used for authentication. If not set we fall-back to using env vars, shared credentials file or AWS Instance metadata
	// https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials
	// +optional
	SecretAccessKey cmmeta.SecretKeySelector `json:"secretAccessKeySecretRef"`

	// Role is a Role ARN which the Route53 provider will assume using either the explicit credentials AccessKeyID/SecretAccessKey
	// or the inferred credentials from environment variables, shared credentials file or AWS Instance metadata
	// +optional
	Role string `json:"role"`

	// If set, the provider will manage only this zone in Route53 and will not do an lookup using the route53:ListHostedZonesByName api call.
	// +optional
	HostedZoneID string `json:"hostedZoneID,omitempty"`

	// Always set the region when using AccessKeyID and SecretAccessKey
	// +kubebuilder:validation:MinLength=1
	Region string `json:"region"`
}

// ACMEIssuerDNS01ProviderAzureDNS is a structure containing the
// configuration for Azure DNS
type ACMEIssuerDNS01ProviderAzureDNS struct {
	// if both this and ClientSecret are left unset MSI will be used
	// +optional
	ClientID string `json:"clientID,omitempty"`

	// if both this and ClientID are left unset MSI will be used
	// +optional
	ClientSecret *cmmeta.SecretKeySelector `json:"clientSecretSecretRef,omitempty"`

	SubscriptionID string `json:"subscriptionID"`

	// when specifying ClientID and ClientSecret then this field is also needed
	// +optional
	TenantID string `json:"tenantID,omitempty"`

	ResourceGroupName string `json:"resourceGroupName"`

	// +optional
	HostedZoneName string `json:"hostedZoneName,omitempty"`

	// +optional
	Environment AzureDNSEnvironment `json:"environment,omitempty"`
}

// +kubebuilder:validation:Enum=AzurePublicCloud;AzureChinaCloud;AzureGermanCloud;AzureUSGovernmentCloud
type AzureDNSEnvironment string

const (
	AzurePublicCloud       AzureDNSEnvironment = "AzurePublicCloud"
	AzureChinaCloud        AzureDNSEnvironment = "AzureChinaCloud"
	AzureGermanCloud       AzureDNSEnvironment = "AzureGermanCloud"
	AzureUSGovernmentCloud AzureDNSEnvironment = "AzureUSGovernmentCloud"
)

// ACMEIssuerDNS01ProviderAcmeDNS is a structure containing the
// configuration for ACME-DNS servers
type ACMEIssuerDNS01ProviderAcmeDNS struct {
	// +kubebuilder:validation:Required
	Host string `json:"host"`

	// +kubebuilder:validation:Required
	AccountSecret cmmeta.SecretKeySelector `json:"accountSecretRef"`
}

// ACMEIssuerDNS01ProviderRFC2136 is a structure containing the
// configuration for RFC2136 DNS
type ACMEIssuerDNS01ProviderRFC2136 struct {
	// The IP address or hostname of an authoritative DNS server supporting
	// RFC2136 in the form host:port. If the host is an IPv6 address it must be
	// enclosed in square brackets (e.g [2001:db8::1]) ; port is optional.
	// This field is required.
	// +kubebuilder:validation:Required
	Nameserver string `json:"nameserver"`

	// The name of the secret containing the TSIG value.
	// If ``tsigKeyName`` is defined, this field is required.
	// +optional
	TSIGSecret cmmeta.SecretKeySelector `json:"tsigSecretSecretRef,omitempty"`

	// The TSIG Key name configured in the DNS.
	// If ``tsigSecretSecretRef`` is defined, this field is required.
	// +optional
	TSIGKeyName string `json:"tsigKeyName,omitempty"`

	// The TSIG Algorithm configured in the DNS supporting RFC2136. Used only
	// when ``tsigSecretSecretRef`` and ``tsigKeyName`` are defined.
	// Supported values are (case-insensitive): ``HMACMD5`` (default),
	// ``HMACSHA1``, ``HMACSHA256`` or ``HMACSHA512``.
	// +optional
	// +kubebuilder:validation:Enum=HMACMD5;HMACSHA1;HMACSHA256;HMACSHA512
	TSIGAlgorithm string `json:"tsigAlgorithm,omitempty"`
}

// ACMEIssuerDNS01ProviderWebhook specifies configuration for a webhook DNS01
// provider, including where to POST ChallengePayload resources.
type ACMEIssuerDNS01ProviderWebhook struct {
	// The API group name that should be used when POSTing ChallengePayload
	// resources to the webhook apiserver.
	// This should be the same as the GroupName specified in the webhook
	// provider implementation.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	GroupName string `json:"groupName"`

	// The name of the solver to use, as defined in the webhook provider
	// implementation.
	// This will typically be the name of the provider, e.g. 'cloudflare'.
	SolverName string `json:"solverName"`

	// Additional configuration that should be passed to the webhook apiserver
	// when challenges are processed.
	// This can contain arbitrary JSON data.
	// Secret values should not be specified in this stanza.
	// If secret values are needed (e.g. credentials for a DNS service), you
	// should use a SecretKeySelector to reference a Secret resource.
	// For details on the schema of this field, consult the webhook provider
	// implementation's documentation.
	// +optional
	Config *apiext.JSON `json:"config,omitempty"`
}

type ACMEIssuerStatus struct {
	// URI is the unique account identifier, which can also be used to retrieve
	// account details from the CA
	// +optional
	URI string `json:"uri,omitempty"`

	// LastRegisteredEmail is the email associated with the latest registered
	// ACME account, in order to track changes made to registered account
	// associated with the  Issuer
	// +optional
	LastRegisteredEmail string `json:"lastRegisteredEmail,omitempty"`
}
