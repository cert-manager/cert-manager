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

package certmanager

// Annotation names for Secrets
const (
	AltNamesAnnotationKey    = "cert-manager.io/alt-names"
	IPSANAnnotationKey       = "cert-manager.io/ip-sans"
	CommonNameAnnotationKey  = "cert-manager.io/common-name"
	IssuerNameAnnotationKey  = "cert-manager.io/issuer-name"
	IssuerKindAnnotationKey  = "cert-manager.io/issuer-kind"
	IssuerGroupAnnotationKey = "cert-manager.io/issuer-group"
	CertificateNameKey       = "cert-manager.io/certificate-name"
)

// Annotation names for CertificateRequests
const (
	CRPrivateKeyAnnotationKey = "cert-manager.io/private-key-secret-name"
)

const (
	ClusterIssuerKind      = "ClusterIssuer"
	IssuerKind             = "Issuer"
	CertificateKind        = "Certificate"
	CertificateRequestKind = "CertificateRequest"
)

const (
	// WantInjectAnnotation is the annotation that specifies that a particular
	// object wants injection of CAs.  It takes the form of a reference to a certificate
	// as namespace/name.  The certificate is expected to have the is-serving-for annotations.
	WantInjectAnnotation = "cert-manager.io/inject-ca-from"

	// WantInjectAPIServerCAAnnotation, if set to "true", will make the cainjector
	// inject the CA certificate for the Kubernetes apiserver into the resource.
	// It discovers the apiserver's CA by inspecting the service account credentials
	// mounted into the cainjector pod.
	WantInjectAPIServerCAAnnotation = "cert-manager.io/inject-apiserver-ca"

	// WantInjectFromSecretAnnotation is the annotation that specifies that a particular
	// object wants injection of CAs.  It takes the form of a reference to a Secret
	// as namespace/name.
	WantInjectFromSecretAnnotation = "cert-manager.io/inject-ca-from-secret"

	// AllowsInjectionFromSecretAnnotation is an annotation that must be added
	// to Secret resource that want to denote that they can be directly
	// injected into injectables that have a `inject-ca-from-secret` annotation.
	// If an injectable references a Secret that does NOT have this annotation,
	// the cainjector will refuse to inject the secret.
	AllowsInjectionFromSecretAnnotation = "cert-manager.io/allow-direct-injection"
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
