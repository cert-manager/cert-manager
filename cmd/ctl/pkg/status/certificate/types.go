/*
Copyright 2020 The Jetstack cert-manager contributors.

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

package certificate

import (
	"crypto/x509"
	"math/big"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/api/core/v1"

	cmapiv1alpha2 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
)

type CertificateStatus struct {
	// Name of the Certificate resource
	Name string
	// Namespace of the Certificate resource
	Namespace string
	// Creation Time of Certificate resource
	CreationTime metav1.Time
	// Conditions of Certificate resource
	Conditions []cmapiv1alpha2.CertificateCondition
	// DNS Names of Certificate resource
	DNSNames []string
	// Events of Certificate resource
	Events *v1.EventList
	// Not Before of Certificate resource
	NotBefore metav1.Time
	// Not After of Certificate resource
	NotAfter metav1.Time
	// Renewal Time of Certificate resource
	RenewalTime metav1.Time

	IssuerStatus *IssuerStatus

	SecretStatus *SecretStatus

	CRStatus *CRStatus
}

type IssuerStatus struct {
	// Name of the Issuer/ClusterIssuer resource
	Name string
	// Kind of the resource, can be Issuer or ClusterIssuer
	Kind string
	// Conditions of Issuer/ClusterIssuer resource
	Conditions []cmapiv1alpha2.IssuerCondition
}

type SecretStatus struct {
	// If Error is not nil, there was a problem getting the status of the Secret resource,
	// but the Secret resource has been found, otherwise this struct would not be created
	Error error
	// Name of the Secret resource
	Name string
	// Issuer Countries of the x509 certificate in the Secret
	IssuerCountry []string
	// Issuer Organisations of the x509 certificate in the Secret
	IssuerOrganisation []string
	// Issuer Common Name of the x509 certificate in the Secret
	IssuerCommonName string
	// Key Usage of the x509 certificate in the Secret
	KeyUsage x509.KeyUsage
	// Extended Key Usage of the x509 certificate in the Secret
	ExtKeyUsage []x509.ExtKeyUsage
	// Public Key Algorithm of the x509 certificate in the Secret
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	// Signature Algorithm of the x509 certificate in the Secret
	SignatureAlgorithm x509.SignatureAlgorithm
	// Subject Key Id of the x509 certificate in the Secret
	SubjectKeyId []byte
	// Authority Key Id of the x509 certificate in the Secret
	AuthorityKeyId []byte
	// Serial Number of the x509 certificate in the Secret
	SerialNumber *big.Int
}

type CRStatus struct {
	// Name of the CertificateRequest resource
	Name string
	// Namespace of the CertificateRequest resource
	Namespace string
	// Conditions of CertificateRequest resource
	Conditions []cmapiv1alpha2.CertificateRequestCondition
	// Events of CertificateRequest resource
	Events *v1.EventList
}