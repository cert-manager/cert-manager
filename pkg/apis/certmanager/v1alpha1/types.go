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

// Annotation names for Secrets
const (
	AltNamesAnnotationKey   = "certmanager.k8s.io/alt-names"
	IPSANAnnotationKey      = "certmanager.k8s.io/ip-sans"
	CommonNameAnnotationKey = "certmanager.k8s.io/common-name"
	IssuerNameAnnotationKey = "certmanager.k8s.io/issuer-name"
	IssuerKindAnnotationKey = "certmanager.k8s.io/issuer-kind"
	CertificateNameKey      = "certmanager.k8s.io/certificate-name"
)

// Annotation names for CertificateRequests
const (
	CRPrivateKeyAnnotationKey = "certmanager.k8s.io/private-key-secret-name"
)

// ConditionStatus represents a condition's status.
// +kubebuilder:validation:Enum=True;False;Unknown
type ConditionStatus string

// These are valid condition statuses. "ConditionTrue" means a resource is in
// the condition; "ConditionFalse" means a resource is not in the condition;
// "ConditionUnknown" means kubernetes can't decide if a resource is in the
// condition or not. In the future, we could add other intermediate
// conditions, e.g. ConditionDegraded.
const (
	// ConditionTrue represents the fact that a given condition is true
	ConditionTrue ConditionStatus = "True"

	// ConditionFalse represents the fact that a given condition is false
	ConditionFalse ConditionStatus = "False"

	// ConditionUnknown represents the fact that a given condition is unknown
	ConditionUnknown ConditionStatus = "Unknown"
)

type LocalObjectReference struct {
	// Name of the referent.
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
	// TODO: Add other useful fields. apiVersion, kind, uid?
	Name string `json:"name"`
}

// ObjectReference is a reference to an object with a given name, kind and group.
type ObjectReference struct {
	Name string `json:"name"`
	// +optional
	Kind string `json:"kind,omitempty"`
	// +optional
	Group string `json:"group,omitempty"`
}

const (
	ClusterIssuerKind      = "ClusterIssuer"
	IssuerKind             = "Issuer"
	CertificateKind        = "Certificate"
	CertificateRequestKind = "CertificateRequest"
	OrderKind              = "Order"
)

type SecretKeySelector struct {
	// The name of the secret in the pod's namespace to select from.
	LocalObjectReference `json:",inline"`
	// The key of the secret to select from. Must be a valid secret key.
	// +optional
	Key string `json:"key,omitempty"`
}

const (
	TLSCAKey = "ca.crt"
)

const (
	// WantInjectAnnotation is the annotation that specifies that a particular
	// object wants injection of CAs.  It takes the form of a reference to a certificate
	// as namespace/name.  The certificate is expected to have the is-serving-for annotations.
	WantInjectAnnotation = "certmanager.k8s.io/inject-ca-from"

	// WantInjectAPIServerCAAnnotation, if set to "true", will make the cainjector
	// inject the CA certificate for the Kubernetes apiserver into the resource.
	// It discovers the apiserver's CA by inspecting the service account credentials
	// mounted into the cainjector pod.
	WantInjectAPIServerCAAnnotation = "certmanager.k8s.io/inject-apiserver-ca"

	// WantInjectFromSecretAnnotation is the annotation that specifies that a particular
	// object wants injection of CAs.  It takes the form of a reference to a Secret
	// as namespace/name.
	WantInjectFromSecretAnnotation = "certmanager.k8s.io/inject-ca-from-secret"

	// AllowsInjectionFromSecretAnnotation is an annotation that must be added
	// to Secret resource that want to denote that they can be directly
	// injected into injectables that have a `inject-ca-from-secret` annotation.
	// If an injectable references a Secret that does NOT have this annotation,
	// the cainjector will refuse to inject the secret.
	AllowsInjectionFromSecretAnnotation = "certmanager.k8s.io/allow-direct-injection"
)

// KeyUsage specifies valid usage contexts for keys.
// See: https://tools.ietf.org/html/rfc5280#section-4.2.1.3
//      https://tools.ietf.org/html/rfc5280#section-4.2.1.12
// +kubebuilder:validation:Enum="signing";"digital signature";"content commitment";"key encipherment";"key agreement";"data encipherment";"cert sign";"crl sign";"encipher only";"decipher only";"any";"server auth";"client auth";"code signing";"email protection";"s/mime";"ipsec end system";"ipsec tunnel";"ipsec user";"timestamping";"ocsp signing";"microsoft sgc";"netscape sgc"
type KeyUsage string

const (
	UsageSigning            KeyUsage = "signing"
	UsageDigitalSignature   KeyUsage = "digital signature"
	UsageContentCommittment KeyUsage = "content commitment"
	UsageKeyEncipherment    KeyUsage = "key encipherment"
	UsageKeyAgreement       KeyUsage = "key agreement"
	UsageDataEncipherment   KeyUsage = "data encipherment"
	UsageCertSign           KeyUsage = "cert sign"
	UsageCRLSign            KeyUsage = "crl sign"
	UsageEncipherOnly       KeyUsage = "encipher only"
	UsageDecipherOnly       KeyUsage = "decipher only"
	UsageAny                KeyUsage = "any"
	UsageServerAuth         KeyUsage = "server auth"
	UsageClientAuth         KeyUsage = "client auth"
	UsageCodeSigning        KeyUsage = "code signing"
	UsageEmailProtection    KeyUsage = "email protection"
	UsageSMIME              KeyUsage = "s/mime"
	UsageIPsecEndSystem     KeyUsage = "ipsec end system"
	UsageIPsecTunnel        KeyUsage = "ipsec tunnel"
	UsageIPsecUser          KeyUsage = "ipsec user"
	UsageTimestamping       KeyUsage = "timestamping"
	UsageOCSPSigning        KeyUsage = "ocsp signing"
	UsageMicrosoftSGC       KeyUsage = "microsoft sgc"
	UsageNetscapSGC         KeyUsage = "netscape sgc"
)

// DefaultKeyUsages contains the default list of key usages
func DefaultKeyUsages() []KeyUsage {
	return []KeyUsage{UsageDigitalSignature, UsageKeyEncipherment}
}
