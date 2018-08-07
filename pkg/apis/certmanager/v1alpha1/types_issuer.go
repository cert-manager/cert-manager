package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
	ACME       *ACMEIssuer       `json:"acme,omitempty"`
	CA         *CAIssuer         `json:"ca,omitempty"`
	Vault      *VaultIssuer      `json:"vault,omitempty"`
	SelfSigned *SelfSignedIssuer `json:"selfSigned,omitempty"`
}

type SelfSignedIssuer struct {
}

type VaultIssuer struct {
	// Vault authentication
	Auth VaultAuth `json:"auth"`
	// Server is the vault connection address
	Server string `json:"server"`
	// Vault URL path to the certificate role
	Path string `json:"path"`
}

// Vault authentication  can be configured:
// - With a secret containing a token. Cert-manager is using this token as-is.
// - With a secret containing a AppRole. This AppRole is used to authenticate to
//   Vault and retrieve a token.
type VaultAuth struct {
	// This Secret contains the Vault token key
	TokenSecretRef SecretKeySelector `json:"tokenSecretRef,omitempty"`
	// This Secret contains a AppRole and Secret
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
	Email string `json:"email"`
	// Server is the ACME server URL
	Server string `json:"server"`
	// If true, skip verifying the ACME server TLS certificate
	SkipTLSVerify bool `json:"skipTLSVerify,omitempty"`
	// PrivateKey is the name of a secret containing the private key for this
	// user account.
	PrivateKey SecretKeySelector `json:"privateKeySecretRef"`
	// HTTP01 config
	HTTP01 *ACMEIssuerHTTP01Config `json:"http01,omitempty"`
	// DNS-01 config
	DNS01 *ACMEIssuerDNS01Config `json:"dns01,omitempty"`
}

type ACMEIssuerHTTP01Config struct {
}

// ACMEIssuerDNS01Config is a structure containing the ACME DNS configuration
// options
type ACMEIssuerDNS01Config struct {
	Providers []ACMEIssuerDNS01Provider `json:"providers"`
}

type ACMEIssuerDNS01Provider struct {
	Name string `json:"name"`

	Akamai     *ACMEIssuerDNS01ProviderAkamai     `json:"akamai,omitempty"`
	CloudDNS   *ACMEIssuerDNS01ProviderCloudDNS   `json:"clouddns,omitempty"`
	Cloudflare *ACMEIssuerDNS01ProviderCloudflare `json:"cloudflare,omitempty"`
	Route53    *ACMEIssuerDNS01ProviderRoute53    `json:"route53,omitempty"`
	AzureDNS   *ACMEIssuerDNS01ProviderAzureDNS   `json:"azuredns,omitempty"`
}

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

// ACMEIssuerDNS01ProviderRoute53 is a structure containing the Route 53
// configuration for AWS
type ACMEIssuerDNS01ProviderRoute53 struct {
	AccessKeyID     string            `json:"accessKeyID"`
	SecretAccessKey SecretKeySelector `json:"secretAccessKeySecretRef"`
	HostedZoneID    string            `json:"hostedZoneID"`
	Region          string            `json:"region"`
}

// ACMEIssuerDNS01ProviderAzureDNS is a structure containing the
// configuration for Azure DNS
type ACMEIssuerDNS01ProviderAzureDNS struct {
	ClientID          string            `json:"clientID"`
	ClientSecret      SecretKeySelector `json:"clientSecretSecretRef"`
	SubscriptionID    string            `json:"subscriptionID"`
	TenantID          string            `json:"tenantID"`
	ResourceGroupName string            `json:"resourceGroupName"`

	// + optional
	HostedZoneName string `json:"hostedZoneName"`
}

// IssuerStatus contains status information about an Issuer
type IssuerStatus struct {
	Conditions []IssuerCondition `json:"conditions"`
	ACME       *ACMEIssuerStatus `json:"acme,omitempty"`
}

type ACMEIssuerStatus struct {
	// URI is the unique account identifier, which can also be used to retrieve
	// account details from the CA
	URI string `json:"uri"`
}

// IssuerCondition contains condition information for an Issuer.
type IssuerCondition struct {
	// Type of the condition, currently ('Ready').
	Type IssuerConditionType `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown').
	Status ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	LastTransitionTime metav1.Time `json:"lastTransitionTime"`

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	Reason string `json:"reason"`

	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	Message string `json:"message"`
}

// IssuerConditionType represents an Issuer condition value.
type IssuerConditionType string

const (
	// IssuerConditionReady represents the fact that a given Issuer condition
	// is in ready state.
	IssuerConditionReady IssuerConditionType = "Ready"
)
