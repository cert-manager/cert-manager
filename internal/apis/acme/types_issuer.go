/*
Copyright 2020 The cert-manager Authors.

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
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapi "sigs.k8s.io/gateway-api/apis/v1alpha2"

	cmmeta "github.com/cert-manager/cert-manager/internal/apis/meta"
)

// ACMEIssuer contains the specification for an ACME issuer.
// This uses the RFC8555 specification to obtain certificates by completing
// 'challenges' to prove ownership of domain identifiers.
// Earlier draft versions of the ACME specification are not supported.
type ACMEIssuer struct {
	// Email is the email address to be associated with the ACME account.
	// This field is optional, but it is strongly recommended to be set.
	// It will be used to contact you in case of issues with your account or
	// certificates, including expiry notification emails.
	// This field may be updated after the account is initially registered.
	Email string

	// Server is the URL used to access the ACME server's 'directory' endpoint.
	// For example, for Let's Encrypt's staging endpoint, you would use:
	// "https://acme-staging-v02.api.letsencrypt.org/directory".
	// Only ACME v2 endpoints (i.e. RFC 8555) are supported.
	Server string

	// PreferredChain is the chain to use if the ACME server outputs multiple.
	// PreferredChain is no guarantee that this one gets delivered by the ACME
	// endpoint.
	// For example, for Let's Encrypt's DST crosssign you would use:
	// "DST Root CA X3" or "ISRG Root X1" for the newer Let's Encrypt root CA.
	PreferredChain string

	// Enables or disables validation of the ACME server TLS certificate.
	// If true, requests to the ACME server will not have their TLS certificate
	// validated (i.e. insecure connections will be allowed).
	// Only enable this option in development environments.
	// The cert-manager system installed roots will be used to verify connections
	// to the ACME server if this is false.
	// Defaults to false.
	SkipTLSVerify bool

	// ExternalAccountBinding is a reference to a CA external account of the ACME
	// server.
	// If set, upon registration cert-manager will attempt to associate the given
	// external account credentials with the registered ACME account.
	ExternalAccountBinding *ACMEExternalAccountBinding

	// PrivateKey is the name of a Kubernetes Secret resource that will be used to
	// store the automatically generated ACME account private key.
	// Optionally, a `key` may be specified to select a specific entry within
	// the named Secret resource.
	// If `key` is not specified, a default of `tls.key` will be used.
	PrivateKey cmmeta.SecretKeySelector

	// Solvers is a list of challenge solvers that will be used to solve
	// ACME challenges for the matching domains.
	// Solver configurations must be provided in order to obtain certificates
	// from an ACME server.
	// For more information, see: https://cert-manager.io/docs/configuration/acme/
	Solvers []ACMEChallengeSolver

	// Enables or disables generating a new ACME account key.
	// If true, the Issuer resource will *not* request a new account but will expect
	// the account key to be supplied via an existing secret.
	// If false, the cert-manager system will generate a new ACME account key
	// for the Issuer.
	// Defaults to false.
	DisableAccountKeyGeneration bool

	// Enables requesting a Not After date on certificates that matches the
	// duration of the certificate. This is not supported by all ACME servers
	// like Let's Encrypt. If set to true when the ACME server does not support
	// it it will create an error on the Order.
	// Defaults to false.
	EnableDurationFeature bool
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
	// The secret key stored in the Secret **must** be un-padded, base64 URL
	// encoded data.
	Key cmmeta.SecretKeySelector

	// Deprecated: keyAlgorithm exists for historical compatibility reasons and
	// should not be used. golang/x/crypto/acme hardcodes the algorithm to HS256
	// so setting this field will have no effect.
	// See https://github.com/cert-manager/cert-manager/issues/3220#issuecomment-809438314
	KeyAlgorithm HMACKeyAlgorithm
}

// HMACKeyAlgorithm is the name of a key algorithm used for HMAC encryption
type HMACKeyAlgorithm string

const (
	HS256 HMACKeyAlgorithm = "HS256"
	HS384 HMACKeyAlgorithm = "HS384"
	HS512 HMACKeyAlgorithm = "HS512"
)

// Configures an issuer to solve challenges using the specified options.
// Only one of HTTP01 or DNS01 may be provided.
type ACMEChallengeSolver struct {
	// Selector selects a set of DNSNames on the Certificate resource that
	// should be solved using this challenge solver.
	// If not specified, the solver will be treated as the 'default' solver
	// with the lowest priority, i.e. if any other solver has a more specific
	// match, it will be used instead.
	Selector *CertificateDNSNameSelector

	// Configures cert-manager to attempt to complete authorizations by
	// performing the HTTP01 challenge flow.
	// It is not possible to obtain certificates for wildcard domain names
	// (e.g. `*.example.com`) using the HTTP01 challenge mechanism.
	HTTP01 *ACMEChallengeSolverHTTP01

	// Configures cert-manager to attempt to complete authorizations by
	// performing the DNS01 challenge flow.
	DNS01 *ACMEChallengeSolverDNS01

	// Configures how cert-manager ensures that the challenge resources have
	// been deployed before it informs an ACME server that it "accepts" the ACME
	// challenge e.g. DNS records or Ingress configurations.
	// The default strategy is "SelfCheck".
	ReadinessStrategy *ChallengeReadinessStrategy

	// If specified, all readiness gates will be evaluated for readiness.
	// The challenge will be accepted only when all conditions specified in the
	// readiness gates have status equal to "True".
	// This allows you to implement your own readiness check in cases where the
	// self-check mechanism does not work and you want something more precise
	// than the "DelayedAccept" readiness strategy.
	// Implement your own Challenge controller which sets a
	// Challenge.Status.Condition e.g. example.com/CustomSelfCheckSucceeded when
	// it has determined that the ACME server will be able to reach the DNS-01
	// or HTTP-01 endpoint for the challenge and set:
	//  readinessStrategy: {}
	//  readinessGates:
	//  - conditionType: example.com/CustomSelfCheckSucceeded
	// Inspired by: https://git.k8s.io/enhancements/keps/sig-network/580-pod-readiness-gates
	ReadinessGates []ChallengeReadinessGate
}

// ChallengeReadinessStrategy contains strategies for ensuring the readiness
// of challenge resources.
type ChallengeReadinessStrategy struct {
	// SelfCheck configures cert-manager to perform a ‘self check’ to ensure
	// that the challenge has ‘propagated’ (i.e. the authoritative DNS servers
	// have been updated to respond correctly, or the changes to the ingress
	// resources have been observed and in-use by the ingress controller).
	// If the self check fails, cert-manager will retry the self check with a
	// fixed 10 second retry interval. Challenges that do not ever complete the
	// self check will continue retrying until the user intervenes by either
	// retrying the Order (by deleting the Order resource) or amending the
	// associated Certificate resource to resolve any configuration errors.
	// Once the self check is passing, the "SelfCheckSucceeded" Condition will be
	// added to the Challenge.Status.Conditions and the ACME ‘authorization’
	// associated with this challenge will be ‘accepted’.
	// SelfCheck is the default challenge readiness strategy.
	// See https://cert-manager.io/docs/concepts/acme-orders-challenges/#challenge-lifecycle
	// +optional
	SelfCheck *ChallengeSelfCheckReadinessStrategy `json:"selfCheck,omitempty"`

	// DelayedAccept configures cert-manager to wait for `timeout` after the
	// Challenge has been created to allow time for the resources to be deployed
	// ("presented") and for them to become ready.
	// Once the timeout is reached, the "DelayedAcceptTimeoutReached" Condition
	// will be added to Challenge.Status.Conditions and the ACME ‘authorization’
	// associated with this challenge will be ‘accepted’.
	// Use this strategy if the "SelfCheck" strategy does not work in your
	// environment; due to hairpin NAT or spit-horizon DNS configurations for
	// example.
	DelayedAccept *ChallengeDelayedAcceptReadinessStrategy `json:"delayedAccept,omitempty"`

	// None configures cert-manager to not use any of its builtin strategies.
	// Use this if you have implemented an external readiness check and
	// configured readinessGates and you do not want to also use any of the
	// builtin strategies.
	None *ChallengeNoReadinessStrategy `json:"none,omitempty"`
}

// ChallengeSelfCheckReadinessStrategy is a ChallengeReadinessStrategy.
type ChallengeSelfCheckReadinessStrategy struct{}

// ChallengeDelayedAcceptReadinessStrategy is a ChallengeReadinessStrategy.
type ChallengeDelayedAcceptReadinessStrategy struct {
	// Timeout is a duration after which the ACME ‘authorization’ associated with
	// this challenge will be ‘accepted’.
	Timeout metav1.Duration `json:"timeout,omitempty"`
}

// ChallengeNoReadinessStrategy is an ChallengeReadinessStrategy.
type ChallengeNoReadinessStrategy struct{}

// ChallengeReadinessGate contains the reference to a challenge condition.
type ChallengeReadinessGate struct {
	// ConditionType refers to a condition in the challenges's condition list with matching type.
	ConditionType ChallengeConditionType `json:"conditionType"`
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

	// The Gateway API is a sig-network community API that models service networking
	// in Kubernetes (https://gateway-api.sigs.k8s.io/). The Gateway solver will
	// create HTTPRoutes with the specified labels in the same namespace as the challenge.
	// This solver is experimental, and fields / behaviour may change in the future.
	// +optional
	GatewayHTTPRoute *ACMEChallengeSolverHTTP01GatewayHTTPRoute
}

type ACMEChallengeSolverHTTP01Ingress struct {
	// Optional service type for Kubernetes solver service. Supported values
	// are NodePort or ClusterIP. If unset, defaults to NodePort.
	// +optional
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

type ACMEChallengeSolverHTTP01GatewayHTTPRoute struct {
	// Optional service type for Kubernetes solver service. Supported values
	// are NodePort or ClusterIP. If unset, defaults to NodePort.
	// +optional
	ServiceType corev1.ServiceType

	// Custom labels that will be applied to HTTPRoutes created by cert-manager
	// while solving HTTP-01 challenges.
	// +optional
	Labels map[string]string

	// When solving an HTTP-01 challenge, cert-manager creates an HTTPRoute.
	// cert-manager needs to know which parentRefs should be used when creating
	// the HTTPRoute. Usually, the parentRef references a Gateway. See:
	// https://gateway-api.sigs.k8s.io/v1alpha2/api-types/httproute/#attaching-to-gateways
	ParentRefs []gwapi.ParentRef
}

type ACMEChallengeSolverHTTP01IngressPodTemplate struct {
	// ObjectMeta overrides for the pod used to solve HTTP01 challenges.
	// Only the 'labels' and 'annotations' fields may be set.
	// If labels or §annotations overlap with in-built values, the values here
	// will override the in-built values.
	ACMEChallengeSolverHTTP01IngressPodObjectMeta

	// PodSpec defines overrides for the HTTP01 challenge solver pod.
	// Only the 'priorityClassName', 'nodeSelector', 'affinity',
	// 'serviceAccountName' and 'tolerations' fields are supported currently.
	// All other fields will be ignored.
	// +optional
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

	// If specified, the pod's priorityClassName.
	PriorityClassName string

	// If specified, the pod's service account
	// +optional
	ServiceAccountName string
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

// Used to configure a DNS01 challenge provider to be used when solving DNS01
// challenges.
// Only one DNS provider may be configured per solver.
type ACMEChallengeSolverDNS01 struct {
	// CNAMEStrategy configures how the DNS01 provider should handle CNAME
	// records when found in DNS zones.
	CNAMEStrategy CNAMEStrategy

	// Use the Akamai DNS zone management API to manage DNS01 challenge records.
	Akamai *ACMEIssuerDNS01ProviderAkamai

	// Use the Google Cloud DNS API to manage DNS01 challenge records.
	CloudDNS *ACMEIssuerDNS01ProviderCloudDNS

	// Use the Cloudflare API to manage DNS01 challenge records.
	Cloudflare *ACMEIssuerDNS01ProviderCloudflare

	// Use the AWS Route53 API to manage DNS01 challenge records.
	Route53 *ACMEIssuerDNS01ProviderRoute53

	// Use the Microsoft Azure DNS API to manage DNS01 challenge records.
	AzureDNS *ACMEIssuerDNS01ProviderAzureDNS

	// Use the DigitalOcean DNS API to manage DNS01 challenge records.
	DigitalOcean *ACMEIssuerDNS01ProviderDigitalOcean

	// Use the 'ACME DNS' (https://github.com/joohoi/acme-dns) API to manage
	// DNS01 challenge records.
	AcmeDNS *ACMEIssuerDNS01ProviderAcmeDNS

	// Use RFC2136 ("Dynamic Updates in the Domain Name System") (https://datatracker.ietf.org/doc/rfc2136/)
	// to manage DNS01 challenge records.
	RFC2136 *ACMEIssuerDNS01ProviderRFC2136

	// Configure an external webhook based DNS01 challenge solver to manage
	// DNS01 challenge records.
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
	HostedZoneName string
}

// ACMEIssuerDNS01ProviderCloudflare is a structure containing the DNS
// configuration for Cloudflare.
// One of `apiKeySecretRef` or `apiTokenSecretRef` must be provided.
type ACMEIssuerDNS01ProviderCloudflare struct {
	// Email of the account, only required when using API key based authentication.
	Email string

	// API key to use to authenticate with Cloudflare.
	// Note: using an API token to authenticate is now the recommended method
	// as it allows greater control of permissions.
	APIKey *cmmeta.SecretKeySelector

	// API token used to authenticate with Cloudflare.
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
	// if both this and ClientSecret are left unset MSI will be used
	ClientID string

	// if both this and ClientID are left unset MSI will be used
	ClientSecret *cmmeta.SecretKeySelector

	SubscriptionID string

	// when specifying ClientID and ClientSecret then this field is also needed
	TenantID string

	ResourceGroupName string

	HostedZoneName string

	Environment AzureDNSEnvironment

	ManagedIdentity *AzureManagedIdentity
}

type AzureManagedIdentity struct {
	ClientID string

	ResourceID string
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
	// should use a SecretKeySelector to reference a Secret resource.
	// For details on the schema of this field, consult the webhook provider
	// implementation's documentation.
	Config *apiextensionsv1.JSON
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
