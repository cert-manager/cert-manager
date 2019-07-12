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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// +kubebuilder:resource:path=clusterissuers
type ClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec   `json:"spec,omitempty"`
	Status IssuerStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterIssuerList is a list of Issuers
type ClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ClusterIssuer `json:"items"`
}

// +genclient
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// +kubebuilder:resource:path=issuers
type Issuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec   `json:"spec,omitempty"`
	Status IssuerStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IssuerList is a list of Issuers
type IssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Issuer `json:"items"`
}

// IssuerSpec is the specification of an Issuer. This includes any
// configuration required for the issuer.
type IssuerSpec struct {
	IssuerConfig `json:",inline"`
}

type IssuerConfig struct {
	// +optional
	ACME *ACMEIssuer `json:"acme,omitempty"`

	// +optional
	CA *CAIssuer `json:"ca,omitempty"`

	// +optional
	Vault *VaultIssuer `json:"vault,omitempty"`

	// +optional
	SelfSigned *SelfSignedIssuer `json:"selfSigned,omitempty"`

	// +optional
	Venafi *VenafiIssuer `json:"venafi,omitempty"`
}

// VenafiIssuer describes issuer configuration details for Venafi Cloud.
type VenafiIssuer struct {
	// Zone is the Venafi Policy Zone to use for this issuer.
	// All requests made to the Venafi platform will be restricted by the named
	// zone policy.
	// This field is required.
	Zone string `json:"zone"`

	// TPP specifies Trust Protection Platform configuration settings.
	// Only one of TPP or Cloud may be specified.
	// +optional
	TPP *VenafiTPP `json:"tpp,omitempty"`

	// Cloud specifies the Venafi cloud configuration settings.
	// Only one of TPP or Cloud may be specified.
	// +optional
	Cloud *VenafiCloud `json:"cloud,omitempty"`
}

// VenafiTPP defines connection configuration details for a Venafi TPP instance
type VenafiTPP struct {
	// URL is the base URL for the Venafi TPP instance
	URL string `json:"url"`

	// CredentialsRef is a reference to a Secret containing the username and
	// password for the TPP server.
	// The secret must contain two keys, 'username' and 'password'.
	CredentialsRef LocalObjectReference `json:"credentialsRef"`

	// CABundle is a PEM encoded TLS certifiate to use to verify connections to
	// the TPP instance.
	// If specified, system roots will not be used and the issuing CA for the
	// TPP instance must be verifiable using the provided root.
	// If not specified, the connection will be verified using the cert-manager
	// system root certificates.
	// +optional
	CABundle []byte `json:"caBundle,omitempty"`
}

// VenafiCloud defines connection configuration details for Venafi Cloud
type VenafiCloud struct {
	// URL is the base URL for Venafi Cloud
	URL string `json:"url"`

	// APITokenSecretRef is a secret key selector for the Venafi Cloud API token.
	APITokenSecretRef SecretKeySelector `json:"apiTokenSecretRef"`
}

type SelfSignedIssuer struct{}

type VaultIssuer struct {
	// Vault authentication
	Auth VaultAuth `json:"auth"`

	// Server is the vault connection address
	Server string `json:"server"`

	// Vault URL path to the certificate role
	Path string `json:"path"`

	// Base64 encoded CA bundle to validate Vault server certificate. Only used
	// if the Server URL is using HTTPS protocol. This parameter is ignored for
	// plain HTTP protocol connection. If not set the system root certificates
	// are used to validate the TLS connection.
	// +optional
	CABundle []byte `json:"caBundle,omitempty"`
}

// Vault authentication  can be configured:
// - With a secret containing a token. Cert-manager is using this token as-is.
// - With a secret containing a AppRole. This AppRole is used to authenticate to
//   Vault and retrieve a token.
type VaultAuth struct {
	// This Secret contains the Vault token key
	// +optional
	TokenSecretRef SecretKeySelector `json:"tokenSecretRef,omitempty"`

	// This Secret contains a AppRole and Secret
	// +optional
	AppRole VaultAppRole `json:"appRole,omitempty"`
}

type VaultAppRole struct {
	// Where the authentication path is mounted in Vault.
	Path string `json:"path"`

	RoleId    string            `json:"roleId"`
	SecretRef SecretKeySelector `json:"secretRef"`
}

type CAIssuer struct {
	// SecretName is the name of the secret used to sign Certificates issued
	// by this Issuer.
	SecretName string `json:"secretName"`
}

// ACMEIssuer contains the specification for an ACME issuer
type ACMEIssuer struct {
	// Email is the email for this account
	// +optional
	Email string `json:"email,omitempty"`

	// Server is the ACME server URL
	Server string `json:"server"`

	// If true, skip verifying the ACME server TLS certificate
	// +optional
	SkipTLSVerify bool `json:"skipTLSVerify,omitempty"`

	// PrivateKey is the name of a secret containing the private key for this
	// user account.
	PrivateKey SecretKeySelector `json:"privateKeySecretRef"`

	// Solvers is a list of challenge solvers that will be used to solve
	// ACME challenges for the matching domains.
	// +optional
	Solvers []ACMEChallengeSolver `json:"solvers,omitempty"`

	// DEPRECATED: HTTP-01 config
	// +optional
	HTTP01 *ACMEIssuerHTTP01Config `json:"http01,omitempty"`

	// DEPRECATED: DNS-01 config
	// +optional
	DNS01 *ACMEIssuerDNS01Config `json:"dns01,omitempty"`
}

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
}

type ACMEChallengeSolverHTTP01IngressPodTemplate struct {
	// ObjectMeta overrides for the pod used to solve HTTP01 challenges.
	// Only the 'labels' and 'annotations' fields may be set.
	// If labels or annotations overlap with in-built values, the values here
	// will override the in-built values.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// PodSpec defines overrides for the HTTP01 challenge solver pod.
	// Only the 'nodeSelector', 'affinity' and 'tolerations' fields are
	// supported currently. All other fields will be ignored.
	// +optional
	Spec ACMEChallengeSolverHTTP01IngressPodSpec `json:"spec,omitempty"`
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

type ACMEChallengeSolverDNS01 struct {
	// CNAMEStrategy configures how the DNS01 provider should handle CNAME
	// records when found in DNS zones.
	// +optional
	// +kubebuilder:validation:Enum=None,Follow
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

/////// OLD TYPES
// TODO: REMOVE THESE IN v0.9

// ACMEIssuerHTTP01Config is a structure containing the ACME HTTP configuration options
type ACMEIssuerHTTP01Config struct {
	// Optional service type for Kubernetes solver service
	// +optional
	ServiceType corev1.ServiceType `json:"serviceType,omitempty"`
}

// ACMEIssuerDNS01Config is a structure containing the ACME DNS configuration
// options
type ACMEIssuerDNS01Config struct {
	// +optional
	Providers []ACMEIssuerDNS01Provider `json:"providers,omitempty"`
}

// ACMEIssuerDNS01Provider contains configuration for a DNS provider that can
// be used to solve ACME DNS01 challenges.
type ACMEIssuerDNS01Provider struct {
	// Name is the name of the DNS provider, which should be used to reference
	// this DNS provider configuration on Certificate resources.
	Name string `json:"name"`

	// CNAMEStrategy configures how the DNS01 provider should handle CNAME
	// records when found in DNS zones.
	// +optional
	// +kubebuilder:validation:Enum=None,Follow
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

//// END OLD TYPES

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
	ServiceConsumerDomain string            `json:"serviceConsumerDomain"`
	ClientToken           SecretKeySelector `json:"clientTokenSecretRef"`
	ClientSecret          SecretKeySelector `json:"clientSecretSecretRef"`
	AccessToken           SecretKeySelector `json:"accessTokenSecretRef"`
}

// ACMEIssuerDNS01ProviderCloudDNS is a structure containing the DNS
// configuration for Google Cloud DNS
type ACMEIssuerDNS01ProviderCloudDNS struct {
	ServiceAccount SecretKeySelector `json:"serviceAccountSecretRef"`
	Project        string            `json:"project"`
}

// ACMEIssuerDNS01ProviderCloudflare is a structure containing the DNS
// configuration for Cloudflare
type ACMEIssuerDNS01ProviderCloudflare struct {
	Email  string            `json:"email"`
	APIKey SecretKeySelector `json:"apiKeySecretRef"`
}

// ACMEIssuerDNS01ProviderDigitalOcean is a structure containing the DNS
// configuration for DigitalOcean Domains
type ACMEIssuerDNS01ProviderDigitalOcean struct {
	Token SecretKeySelector `json:"tokenSecretRef"`
}

// ACMEIssuerDNS01ProviderRoute53 is a structure containing the Route 53
// configuration for AWS
type ACMEIssuerDNS01ProviderRoute53 struct {
	AccessKeyID string `json:"accessKeyID"`

	SecretAccessKey SecretKeySelector `json:"secretAccessKeySecretRef"`

	// +optional
	HostedZoneID string `json:"hostedZoneID,omitempty"`

	Region string `json:"region"`
}

// ACMEIssuerDNS01ProviderAzureDNS is a structure containing the
// configuration for Azure DNS
type ACMEIssuerDNS01ProviderAzureDNS struct {
	ClientID string `json:"clientID"`

	ClientSecret SecretKeySelector `json:"clientSecretSecretRef"`

	SubscriptionID string `json:"subscriptionID"`

	TenantID string `json:"tenantID"`

	ResourceGroupName string `json:"resourceGroupName"`

	// +optional
	HostedZoneName string `json:"hostedZoneName,omitempty"`

	// +kubebuilder:validation:Enum=,AzurePublicCloud,AzureChinaCloud,AzureGermanCloud,AzureUSGovernmentCloud
	// +optional
	Environment string `json:"environment,omitempty"`
}

// ACMEIssuerDNS01ProviderAcmeDNS is a structure containing the
// configuration for ACME-DNS servers
type ACMEIssuerDNS01ProviderAcmeDNS struct {
	Host string `json:"host"`

	AccountSecret SecretKeySelector `json:"accountSecretRef"`
}

// ACMEIssuerDNS01ProviderRFC2136 is a structure containing the
// configuration for RFC2136 DNS
type ACMEIssuerDNS01ProviderRFC2136 struct {
	// The IP address of the DNS supporting RFC2136. Required.
	// Note: FQDN is not a valid value, only IP.
	Nameserver string `json:"nameserver"`

	// The name of the secret containing the TSIG value.
	// If ``tsigKeyName`` is defined, this field is required.
	// +optional
	TSIGSecret SecretKeySelector `json:"tsigSecretSecretRef,omitempty"`

	// The TSIG Key name configured in the DNS.
	// If ``tsigSecretSecretRef`` is defined, this field is required.
	// +optional
	TSIGKeyName string `json:"tsigKeyName,omitempty"`

	// The TSIG Algorithm configured in the DNS supporting RFC2136. Used only
	// when ``tsigSecretSecretRef`` and ``tsigKeyName`` are defined.
	// Supported values are (case-insensitive): ``HMACMD5`` (default),
	// ``HMACSHA1``, ``HMACSHA256`` or ``HMACSHA512``.
	// +optional
	TSIGAlgorithm string `json:"tsigAlgorithm,omitempty"`
}

// ACMEIssuerDNS01ProviderWebhook specifies configuration for a webhook DNS01
// provider, including where to POST ChallengePayload resources.
type ACMEIssuerDNS01ProviderWebhook struct {
	// The API group name that should be used when POSTing ChallengePayload
	// resources to the webhook apiserver.
	// This should be the same as the GroupName specified in the webhook
	// provider implementation.
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

// IssuerStatus contains status information about an Issuer
type IssuerStatus struct {
	// +optional
	Conditions []IssuerCondition `json:"conditions,omitempty"`

	// +optional
	ACME *ACMEIssuerStatus `json:"acme,omitempty"`
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

// IssuerCondition contains condition information for an Issuer.
type IssuerCondition struct {
	// Type of the condition, currently ('Ready').
	Type IssuerConditionType `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown').
	// +kubebuilder:validation:Enum=True,False,Unknown
	Status ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	// +optional
	Reason string `json:"reason,omitempty"`

	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	// +optional
	Message string `json:"message,omitempty"`
}

// IssuerConditionType represents an Issuer condition value.
type IssuerConditionType string

const (
	// IssuerConditionReady represents the fact that a given Issuer condition
	// is in ready state.
	IssuerConditionReady IssuerConditionType = "Ready"
)
