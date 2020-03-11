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

package acme

import (
	corev1 "k8s.io/api/core/v1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"

	cmmeta "github.com/jetstack/cert-manager/pkg/internal/apis/meta"
)

// ACMEIssuer contains the specification for an ACME issuer
type ACMEIssuer struct {
	// Email is the email for this account
	Email string

	// Server is the ACME server URL
	Server string

	// If true, skip verifying the ACME server TLS certificate
	SkipTLSVerify bool

	// ExternalAccountBinding is a reference to a CA external account of the ACME
	// server.
	ExternalAccountBinding *ACMEExternalAccountBinding

	// PrivateKey is the name of a secret containing the private key for this
	// user account.
	PrivateKey cmmeta.SecretKeySelector

	// Solvers is a list of challenge solvers that will be used to solve
	// ACME challenges for the matching domains.
	Solvers []ACMEChallengeSolver
}

// ACMEExternalAccountBinding is a reference to a CA external account of the ACME
// server.
type ACMEExternalAccountBinding struct {
	// keyID is the ID of the CA key that the External Account is bound to.
	KeyID string

	// keySecretRef is a Secret Key Selector referencing a data item in a Kubernetes
	// Secret which holds the symmetric MAC key of the External Account Binding.
	// The `key` is the index string that is paired with the key data in the
	// Secret and should not be confused with the key data itself, or indeed with
	// the External Account Binding keyID above.
	Key cmmeta.SecretKeySelector

	// keyAlgorithm is the MAC key algorithm that the key is used for. Valid
	// values are "HS256", "HS384" and "HS512".
	KeyAlgorithm HMACKeyAlgorithm
}

// HMACKeyAlgorithm is the name of a key algorithm used for HMAC encryption
type HMACKeyAlgorithm string

const (
	HS256 HMACKeyAlgorithm = "HS256"
	HS384 HMACKeyAlgorithm = "HS384"
	HS512 HMACKeyAlgorithm = "HS512"
)

type ACMEChallengeSolver struct {
	// Selector selects a set of DNSNames on the Certificate resource that
	// should be solved using this challenge solver.
	Selector *CertificateDNSNameSelector

	HTTP01 *ACMEChallengeSolverHTTP01

	DNS01 *ACMEChallengeSolverDNS01
}

// CertificateDomainSelector selects certificates using a label selector, and
// can optionally select individual DNS names within those certificates.
// If both MatchLabels and DNSNames are empty, this selector will match all
// certificates and DNS names within them.
type CertificateDNSNameSelector struct {
	// A label selector that is used to refine the set of certificate's that
	// this challenge solver will apply to.
	MatchLabels map[string]string

	// List of DNSNames that this solver will be used to solve.
	// If specified and a match is found, a dnsNames selector will take
	// precedence over a dnsZones selector.
	// If multiple solvers match with the same dnsNames value, the solver
	// with the most matching labels in matchLabels will be selected.
	// If neither has more matches, the solver defined earlier in the list
	// will be selected.
	DNSNames []string

	// List of DNSZones that this solver will be used to solve.
	// The most specific DNS zone match specified here will take precedence
	// over other DNS zone matches, so a solver specifying sys.example.com
	// will be selected over one specifying example.com for the domain
	// www.sys.example.com.
	// If multiple solvers match with the same dnsZones value, the solver
	// with the most matching labels in matchLabels will be selected.
	// If neither has more matches, the solver defined earlier in the list
	// will be selected.
	DNSZones []string
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
	Ingress *ACMEChallengeSolverHTTP01Ingress
}

type ACMEChallengeSolverHTTP01Ingress struct {
	// Optional service type for Kubernetes solver service
	ServiceType corev1.ServiceType

	// The ingress class to use when creating Ingress resources to solve ACME
	// challenges that use this challenge solver.
	// Only one of 'class' or 'name' may be specified.
	Class *string

	// The name of the ingress resource that should have ACME challenge solving
	// routes inserted into it in order to solve HTTP01 challenges.
	// This is typically used in conjunction with ingress controllers like
	// ingress-gce, which maintains a 1:1 mapping between external IPs and
	// ingress resources.
	Name string

	// Optional pod template used to configure the ACME challenge solver pods
	// used for HTTP01 challenges
	PodTemplate *ACMEChallengeSolverHTTP01IngressPodTemplate

	// Optional ingress template used to configure the ACME challenge solver
	// ingress used for HTTP01 challenges
	IngressTemplate *ACMEChallengeSolverHTTP01IngressTemplate
}

type ACMEChallengeSolverHTTP01IngressPodTemplate struct {
	// ObjectMeta overrides for the pod used to solve HTTP01 challenges.
	// Only the 'labels' and 'annotations' fields may be set.
	// If labels or annotations overlap with in-built values, the values here
	// will override the in-built values.
	ACMEChallengeSolverHTTP01IngressPodObjectMeta

	// PodSpec defines overrides for the HTTP01 challenge solver pod.
	// Only the 'nodeSelector', 'affinity' and 'tolerations' fields are
	// supported currently. All other fields will be ignored.
	Spec ACMEChallengeSolverHTTP01IngressPodSpec
}

type ACMEChallengeSolverHTTP01IngressPodObjectMeta struct {
	// Annotations that should be added to the create ACME HTTP01 solver pods.
	Annotations map[string]string

	// Labels that should be added to the created ACME HTTP01 solver pods.
	Labels map[string]string
}

type ACMEChallengeSolverHTTP01IngressPodSpec struct {
	// NodeSelector is a selector which must be true for the pod to fit on a node.
	// Selector which must match a node's labels for the pod to be scheduled on that node.
	// More info: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
	NodeSelector map[string]string

	// If specified, the pod's scheduling constraints
	Affinity *corev1.Affinity

	// If specified, the pod's tolerations.
	Tolerations []corev1.Toleration
}

type ACMEChallengeSolverHTTP01IngressTemplate struct {
	// ObjectMeta overrides for the ingress used to solve HTTP01 challenges.
	// Only the 'labels' and 'annotations' fields may be set.
	// If labels or annotations overlap with in-built values, the values here
	// will override the in-built values.
	ACMEChallengeSolverHTTP01IngressObjectMeta
}

type ACMEChallengeSolverHTTP01IngressObjectMeta struct {
	// Annotations that should be added to the created ACME HTTP01 solver ingress.
	Annotations map[string]string

	// Labels that should be added to the created ACME HTTP01 solver ingress.
	Labels map[string]string
}

type ACMEChallengeSolverDNS01 struct {
	// CNAMEStrategy configures how the DNS01 provider should handle CNAME
	// records when found in DNS zones.
	CNAMEStrategy CNAMEStrategy

	Akamai *ACMEIssuerDNS01ProviderAkamai

	CloudDNS *ACMEIssuerDNS01ProviderCloudDNS

	Cloudflare *ACMEIssuerDNS01ProviderCloudflare

	Route53 *ACMEIssuerDNS01ProviderRoute53

	AzureDNS *ACMEIssuerDNS01ProviderAzureDNS

	DigitalOcean *ACMEIssuerDNS01ProviderDigitalOcean

	AcmeDNS *ACMEIssuerDNS01ProviderAcmeDNS

	RFC2136 *ACMEIssuerDNS01ProviderRFC2136

	Webhook *ACMEIssuerDNS01ProviderWebhook
}

// CNAMEStrategy configures how the DNS01 provider should handle CNAME records
// when found in DNS zones.
// By default, the None strategy will be applied (i.e. do not follow CNAMEs).
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
	ServiceConsumerDomain string
	ClientToken           cmmeta.SecretKeySelector
	ClientSecret          cmmeta.SecretKeySelector
	AccessToken           cmmeta.SecretKeySelector
}

// ACMEIssuerDNS01ProviderCloudDNS is a structure containing the DNS
// configuration for Google Cloud DNS
type ACMEIssuerDNS01ProviderCloudDNS struct {
	ServiceAccount *cmmeta.SecretKeySelector
	Project        string
}

// ACMEIssuerDNS01ProviderCloudflare is a structure containing the DNS
// configuration for Cloudflare
type ACMEIssuerDNS01ProviderCloudflare struct {
	Email    string
	APIKey   *cmmeta.SecretKeySelector
	APIToken *cmmeta.SecretKeySelector
}

// ACMEIssuerDNS01ProviderDigitalOcean is a structure containing the DNS
// configuration for DigitalOcean Domains
type ACMEIssuerDNS01ProviderDigitalOcean struct {
	Token cmmeta.SecretKeySelector
}

// ACMEIssuerDNS01ProviderRoute53 is a structure containing the Route 53
// configuration for AWS
type ACMEIssuerDNS01ProviderRoute53 struct {
	// The AccessKeyID is used for authentication. If not set we fall-back to using env vars, shared credentials file or AWS Instance metadata
	// see: https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials
	AccessKeyID string

	// The SecretAccessKey is used for authentication. If not set we fall-back to using env vars, shared credentials file or AWS Instance metadata
	// https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials
	SecretAccessKey cmmeta.SecretKeySelector

	// Role is a Role ARN which the Route53 provider will assume using either the explicit credentials AccessKeyID/SecretAccessKey
	// or the inferred credentials from environment variables, shared credentials file or AWS Instance metadata
	Role string

	// If set, the provider will manage only this zone in Route53 and will not do an lookup using the route53:ListHostedZonesByName api call.
	HostedZoneID string

	// Always set the region when using AccessKeyID and SecretAccessKey
	Region string
}

// ACMEIssuerDNS01ProviderAzureDNS is a structure containing the
// configuration for Azure DNS
type ACMEIssuerDNS01ProviderAzureDNS struct {
	ClientID string

	ClientSecret *cmmeta.SecretKeySelector

	SubscriptionID string

	TenantID string

	ResourceGroupName string

	HostedZoneName string

	Environment AzureDNSEnvironment
}

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
	Host string

	AccountSecret cmmeta.SecretKeySelector
}

// ACMEIssuerDNS01ProviderRFC2136 is a structure containing the
// configuration for RFC2136 DNS
type ACMEIssuerDNS01ProviderRFC2136 struct {
	// The IP address or hostname of an authoritative DNS server supporting
	// RFC2136 in the form host:port. If the host is an IPv6 address it must be
	// enclosed in square brackets (e.g [2001:db8::1]) ; port is optional.
	// This field is required.
	Nameserver string

	// The name of the secret containing the TSIG value.
	// If ``tsigKeyName`` is defined, this field is required.
	TSIGSecret cmmeta.SecretKeySelector

	// The TSIG Key name configured in the DNS.
	// If ``tsigSecretSecretRef`` is defined, this field is required.
	TSIGKeyName string

	// The TSIG Algorithm configured in the DNS supporting RFC2136. Used only
	// when ``tsigSecretSecretRef`` and ``tsigKeyName`` are defined.
	// Supported values are (case-insensitive): ``HMACMD5`` (default),
	// ``HMACSHA1``, ``HMACSHA256`` or ``HMACSHA512``.
	TSIGAlgorithm string
}

// ACMEIssuerDNS01ProviderWebhook specifies configuration for a webhook DNS01
// provider, including where to POST ChallengePayload resources.
type ACMEIssuerDNS01ProviderWebhook struct {
	// The API group name that should be used when POSTing ChallengePayload
	// resources to the webhook apiserver.
	// This should be the same as the GroupName specified in the webhook
	// provider implementation.
	GroupName string

	// The name of the solver to use, as defined in the webhook provider
	// implementation.
	// This will typically be the name of the provider, e.g. 'cloudflare'.
	SolverName string

	// Additional configuration that should be passed to the webhook apiserver
	// when challenges are processed.
	// This can contain arbitrary JSON data.
	// Secret values should not be specified in this stanza.
	// If secret values are needed (e.g. credentials for a DNS service), you
	// should use a cmmeta.SecretKeySelector to reference a Secret resource.
	// For details on the schema of this field, consult the webhook provider
	// implementation's documentation.
	Config *apiext.JSON
}

type ACMEIssuerStatus struct {
	// URI is the unique account identifier, which can also be used to retrieve
	// account details from the CA
	URI string

	// LastRegisteredEmail is the email associated with the latest registered
	// ACME account, in order to track changes made to registered account
	// associated with the  Issuer
	LastRegisteredEmail string
}
