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

package certmanager

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmacme "github.com/cert-manager/cert-manager/internal/apis/acme"
	cmmeta "github.com/cert-manager/cert-manager/internal/apis/meta"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// A ClusterIssuer represents a certificate issuing authority which can be
// referenced as part of `issuerRef` fields.
// It is similar to an Issuer, however it is cluster-scoped and therefore can
// be referenced by resources that exist in *any* namespace, not just the same
// namespace as the referent.
type ClusterIssuer struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	// Desired state of the ClusterIssuer resource.
	Spec IssuerSpec

	// Status of the ClusterIssuer. This is set and managed automatically.
	Status IssuerStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterIssuerList is a list of Issuers
type ClusterIssuerList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []ClusterIssuer
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// An Issuer represents a certificate issuing authority which can be
// referenced as part of `issuerRef` fields.
// It is scoped to a single namespace and can therefore only be referenced by
// resources within the same namespace.
type Issuer struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	// Desired state of the Issuer resource.
	Spec IssuerSpec

	// Status of the Issuer. This is set and managed automatically.
	Status IssuerStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IssuerList is a list of Issuers
type IssuerList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []Issuer
}

// IssuerSpec is the specification of an Issuer. This includes any
// configuration required for the issuer.
type IssuerSpec struct {
	IssuerConfig
}

// IssuerConfig is a generic wrapper around custom issuer types
type IssuerConfig struct {
	// ACME configures this issuer to communicate with a RFC8555 (ACME) server
	// to obtain signed x509 certificates.
	ACME *cmacme.ACMEIssuer

	// CA configures this issuer to sign certificates using a signing CA keypair
	// stored in a Secret resource.
	// This is used to build internal PKIs that are managed by cert-manager.
	CA *CAIssuer

	// Vault configures this issuer to sign certificates using a HashiCorp Vault
	// PKI backend.
	Vault *VaultIssuer

	// SelfSigned configures this issuer to 'self sign' certificates using the
	// private key used to create the CertificateRequest object.
	SelfSigned *SelfSignedIssuer

	// Venafi configures this issuer to sign certificates using a Venafi TPP
	// or Venafi Cloud policy zone.
	Venafi *VenafiIssuer
}

// VenafiIssuer configures an issuer to sign certificates using a Venafi TPP
// or Cloud policy zone.
type VenafiIssuer struct {
	// Zone is the Venafi Policy Zone to use for this issuer.
	// All requests made to the Venafi platform will be restricted by the named
	// zone policy.
	// This field is required.
	Zone string

	// TPP specifies Trust Protection Platform configuration settings.
	// Only one of TPP or Cloud may be specified.
	TPP *VenafiTPP

	// Cloud specifies the Venafi cloud configuration settings.
	// Only one of TPP or Cloud may be specified.
	Cloud *VenafiCloud
}

// VenafiTPP defines connection configuration details for a Venafi TPP instance
type VenafiTPP struct {
	// URL is the base URL for the vedsdk endpoint of the Venafi TPP instance,
	// for example: "https://tpp.example.com/vedsdk".
	URL string

	// CredentialsRef is a reference to a Secret containing the username and
	// password for the TPP server.
	// The secret must contain two keys, 'username' and 'password'.
	CredentialsRef cmmeta.LocalObjectReference

	// Base64-encoded bundle of PEM CAs which will be used to validate the certificate
	// chain presented by the TPP server. Only used if using HTTPS; ignored for HTTP.
	// If undefined, the certificate bundle in the cert-manager controller container
	// is used to validate the chain.
	CABundle []byte
}

// VenafiCloud defines connection configuration details for Venafi Cloud
type VenafiCloud struct {
	// URL is the base URL for Venafi Cloud.
	// Defaults to "https://api.venafi.cloud/v1".
	URL string

	// APITokenSecretRef is a secret key selector for the Venafi Cloud API token.
	APITokenSecretRef cmmeta.SecretKeySelector
}

// SelfSignedIssuer configures an issuer to 'self sign' certificates using the
// private key used to create the CertificateRequest object.
type SelfSignedIssuer struct {
	// The CRL distribution points is an X.509 v3 certificate extension which identifies
	// the location of the CRL from which the revocation of this certificate can be checked.
	// If not set certificate will be issued without CDP. Values are strings.
	CRLDistributionPoints []string
}

// VaultIssuer configures an issuer to sign certificates using a HashiCorp Vault
// PKI backend.
type VaultIssuer struct {
	// Auth configures how cert-manager authenticates with the Vault server.
	Auth VaultAuth

	// Server is the connection address for the Vault server, e.g: "https://vault.example.com:8200".
	Server string

	// Path is the mount path of the Vault PKI backend's `sign` endpoint, e.g:
	// "my_pki_mount/sign/my-role-name".
	Path string

	// Name of the vault namespace. Namespaces is a set of features within Vault Enterprise that allows Vault environments to support Secure Multi-tenancy. e.g: "ns1"
	// More about namespaces can be found here https://www.vaultproject.io/docs/enterprise/namespaces
	Namespace string

	// Base64-encoded bundle of PEM CAs which will be used to validate the certificate
	// chain presented by Vault. Only used if using HTTPS to connect to Vault and
	// ignored for HTTP connections.
	// Mutually exclusive with CABundleSecretRef.
	// If neither CABundle nor CABundleSecretRef are defined, the certificate bundle in
	// the cert-manager controller container is used to validate the TLS connection.
	// +optional
	CABundle []byte

	// Reference to a Secret containing a bundle of PEM-encoded CAs to use when
	// verifying the certificate chain presented by Vault when using HTTPS.
	// Mutually exclusive with CABundle.
	// If neither CABundle nor CABundleSecretRef are defined, the certificate bundle in
	// the cert-manager controller container is used to validate the TLS connection.
	// If no key for the Secret is specified, cert-manager will default to 'ca.crt'.
	// +optional
	CABundleSecretRef *cmmeta.SecretKeySelector
}

// VaultAuth is configuration used to authenticate with a Vault server. The
// order of precedence is [`tokenSecretRef`, `appRole` or `kubernetes`].
type VaultAuth struct {
	// TokenSecretRef authenticates with Vault by presenting a token.
	TokenSecretRef *cmmeta.SecretKeySelector

	// AppRole authenticates with Vault using the App Role auth mechanism,
	// with the role and secret stored in a Kubernetes Secret resource.
	AppRole *VaultAppRole

	// Kubernetes authenticates with Vault by passing the ServiceAccount
	// token stored in the named Secret resource to the Vault server.
	Kubernetes *VaultKubernetesAuth
}

// VaultAppRole authenticates with Vault using the App Role auth mechanism,
// with the role and secret stored in a Kubernetes Secret resource.
type VaultAppRole struct {
	// Path where the App Role authentication backend is mounted in Vault, e.g:
	// "approle"
	Path string

	// RoleID configured in the App Role authentication backend when setting
	// up the authentication backend in Vault.
	RoleId string

	// Reference to a key in a Secret that contains the App Role secret used
	// to authenticate with Vault.
	// The `key` field must be specified and denotes which entry within the Secret
	// resource is used as the app role secret.
	SecretRef cmmeta.SecretKeySelector
}

// Authenticate against Vault using a Kubernetes ServiceAccount token stored in
// a Secret.
type VaultKubernetesAuth struct {
	// The Vault mountPath here is the mount path to use when authenticating with
	// Vault. For example, setting a value to `/v1/auth/foo`, will use the path
	// `/v1/auth/foo/login` to authenticate with Vault. If unspecified, the
	// default value "/v1/auth/kubernetes" will be used.
	Path string

	// The required Secret field containing a Kubernetes ServiceAccount JWT used
	// for authenticating with Vault. Use of 'ambient credentials' is not
	// supported. This field should not be set if serviceAccountRef is set.
	// +optional
	SecretRef cmmeta.SecretKeySelector
	// Note: we don't use a pointer here for backwards compatibility.

	// A reference to a service account that will be used to request a bound
	// token (also known as "projected token"). Compared to using "secretRef",
	// using this field means that you don't rely on statically bound tokens. To
	// use this field, you must configure an RBAC rule to let cert-manager
	// request a token.
	// +optional
	ServiceAccountRef *ServiceAccountRef

	// A required field containing the Vault Role to assume. A Role binds a
	// Kubernetes ServiceAccount with a set of Vault policies.
	Role string
}

// ServiceAccountRef is a service account used by cert-manager to request a
// token. The audience cannot be configured. The audience is generated by
// cert-manager and takes the form `vault://namespace-name/issuer-name` for an
// Issuer and `vault://issuer-name` for a ClusterIssuer. The expiration of the
// token is also set by cert-manager to 10 minutes.
type ServiceAccountRef struct {
	// Name of the ServiceAccount used to request a token.
	Name string
}

// CAIssuer configures an issuer that can issue certificates from its provided
// CA certificate. It contains the name of the private key to sign certificates,
// holds the location for Certificate Revocation Lists (CRL) distribution
// points and list of URLs of Online Certificate Status Protocol (OCSP)
// responders.
type CAIssuer struct {
	// SecretName is the name of the secret used to sign Certificates issued
	// by this Issuer.
	SecretName string

	// The CRL distribution points is an X.509 v3 certificate extension which identifies
	// the location of the CRL from which the revocation of this certificate can be checked.
	// If not set, certificates will be issued without distribution points set.
	CRLDistributionPoints []string

	// The OCSP server list is an X.509 v3 extension that defines a list of
	// URLs of OCSP responders. The OCSP responders can be queried for the
	// revocation status of an issued certificate. If not set, the
	// certificate will be issued with no OCSP servers set. For example, an
	// OCSP server URL could be "http://ocsp.int-x3.letsencrypt.org".
	OCSPServers []string

	// IssuingCertificateURLs is a list of URLs which this issuer should embed into certificates
	// it creates. See https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1 for more details.
	// As an example, such a URL might be "http://ca.domain.com/ca.crt".
	// +optional
	IssuingCertificateURLs []string `json:"issuingCertificateURLs,omitempty"`
}

// IssuerStatus contains status information about an Issuer
type IssuerStatus struct {
	// List of status conditions to indicate the status of a CertificateRequest.
	// Known condition types are `Ready`.
	Conditions []IssuerCondition

	// ACME specific status options.
	// This field should only be set if the Issuer is configured to use an ACME
	// server to issue certificates.
	ACME *cmacme.ACMEIssuerStatus
}

// IssuerCondition contains condition information for an Issuer.
type IssuerCondition struct {
	// Type of the condition, known values are (`Ready`).
	Type IssuerConditionType

	// Status of the condition, one of (`True`, `False`, `Unknown`).
	Status cmmeta.ConditionStatus

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	LastTransitionTime *metav1.Time

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	Reason string

	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	Message string

	// If set, this represents the .metadata.generation that the condition was
	// set based upon.
	// For instance, if .metadata.generation is currently 12, but the
	// .status.condition[x].observedGeneration is 9, the condition is out of date
	// with respect to the current state of the Issuer.
	ObservedGeneration int64
}

// IssuerConditionType represents an Issuer condition value.
type IssuerConditionType string

const (
	// IssuerConditionReady represents the fact that a given Issuer condition
	// is in ready state and able to issue certificates.
	// If the `status` of this condition is `False`, CertificateRequest controllers
	// should prevent attempts to sign certificates.
	IssuerConditionReady IssuerConditionType = "Ready"
)
