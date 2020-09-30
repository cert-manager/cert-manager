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

package validations

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/pki"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"

	corev1 "k8s.io/api/core/v1"
)

// Expect2Or3KeysInSecret checks if the secret resource has the correct amount of fields in the secret data
func Expect2Or3KeysInSecret(_ *cmapi.Certificate, secret *corev1.Secret) error {
	if !(len(secret.Data) == 2 || len(secret.Data) == 3) {
		return fmt.Errorf("Expected 2 keys in certificate secret, but there was %d", len(secret.Data))
	}

	return nil
}

// ExpectValidAnnotations checks if the correct annotations on the secret are present
func ExpectValidAnnotations(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	label, ok := secret.Annotations[cmapi.CertificateNameKey]
	if !ok {
		return fmt.Errorf("Expected secret to have certificate-name label, but had none")
	}

	if label != certificate.Name {
		return fmt.Errorf("Expected secret to have certificate-name label with a value of %q, but got %q", certificate.Name, label)
	}

	return nil
}

// ExpectValidPrivateKeyData checks of the secret's private key matches the request
func ExpectValidPrivateKeyData(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	keyBytes, ok := secret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		return fmt.Errorf("No private key data found for Certificate %q (secret %q)", certificate.Name, certificate.Spec.SecretName)
	}
	key, err := pki.DecodePrivateKeyBytes(keyBytes)
	if err != nil {
		return err
	}

	// validate private key is of the correct type (rsa or ecdsa)
	if certificate.Spec.PrivateKey != nil {
		switch certificate.Spec.PrivateKey.Algorithm {
		case cmapi.PrivateKeyAlgorithm(""),
			cmapi.RSAKeyAlgorithm:
			_, ok := key.(*rsa.PrivateKey)
			if !ok {
				return fmt.Errorf("Expected private key of type RSA, but it was: %T", key)
			}
		case cmapi.ECDSAKeyAlgorithm:
			_, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				return fmt.Errorf("Expected private key of type ECDSA, but it was: %T", key)
			}
		default:
			return fmt.Errorf("unrecognised requested private key algorithm %q", certificate.Spec.PrivateKey.Algorithm)
		}
	}

	// TODO: validate private key KeySize
	return nil
}

// ExpectValidCertificate checks if the certificate is a valid x509 certificate
func ExpectValidCertificate(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	certBytes, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		return fmt.Errorf("No certificate data found for Certificate %q (secret %q)", certificate.Name, certificate.Spec.SecretName)
	}

	_, err := pki.DecodeX509CertificateBytes(certBytes)
	if err != nil {
		return err
	}

	return nil
}

// ExpectCertificateOrganizationToMatch checks if the issued certificate has the same Organization as the requested one
func ExpectCertificateOrganizationToMatch(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return err
	}

	expectedOrganization := pki.OrganizationForCertificate(certificate)
	if !util.EqualUnsorted(cert.Subject.Organization, expectedOrganization) {
		return fmt.Errorf("Expected certificate valid for O %v, but got a certificate valid for O %v", expectedOrganization, cert.Subject.Organization)
	}

	return nil
}

// ExpectCertificateDNSNamesToMatch checks if the issued certificate has all DNS names it requested
func ExpectCertificateDNSNamesToMatch(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return err
	}

	expectedDNSNames := certificate.Spec.DNSNames
	if !util.Subset(cert.DNSNames, expectedDNSNames) {
		return fmt.Errorf("Expected certificate valid for DNSNames %v, but got a certificate valid for DNSNames %v", expectedDNSNames, cert.DNSNames)
	}

	return nil
}

// ExpectCertificateDNSNamesToMatch checks if the issued certificate has all URI SANs names it requested
func ExpectCertificateURIsToMatch(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return err
	}

	uris, err := pki.URIsForCertificate(certificate)
	if err != nil {
		return fmt.Errorf("failed to parse URIs: %s", err)
	}
	expectedURIs := pki.URLsToString(uris)
	if !util.EqualUnsorted(pki.URLsToString(cert.URIs), expectedURIs) {
		return fmt.Errorf("Expected certificate valid for URIs %v, but got a certificate valid for URIs %v", expectedURIs, pki.URLsToString(cert.URIs))
	}

	return nil
}

// ExpectValidCommonName checks if the issued certificate has the requested CN or one of the DNS SANs
func ExpectValidCommonName(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return err
	}

	expectedCN := certificate.Spec.CommonName

	if len(expectedCN) == 0 && len(cert.Subject.CommonName) > 0 {
		// no CN is specified but our CA set one, checking if it is one of our DNS names
		if !util.Contains(cert.DNSNames, cert.Subject.CommonName) {
			return fmt.Errorf("Expected a common name for one of our DNSNames %v, but got a CN of %v", cert.DNSNames, cert.Subject.CommonName)
		}
	} else if expectedCN != cert.Subject.CommonName {
		return fmt.Errorf("Expected a common name of %v, but got a CN of %v", expectedCN, cert.Subject.CommonName)
	}

	return nil
}

// ExpectValidNotAfterDate checks if the issued certificate matches the requested duration
func ExpectValidNotAfterDate(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return err
	}
	if certificate.Status.NotAfter == nil {
		return fmt.Errorf("No certificate expiration found for Certificate %q", certificate.Name)
	}

	if !cert.NotAfter.Equal(certificate.Status.NotAfter.Time) {
		return fmt.Errorf("Expected certificate expiry date to be %v, but got %v", certificate.Status.NotAfter, cert.NotAfter)
	}

	return nil
}

func containsExtKeyUsage(s []x509.ExtKeyUsage, e x509.ExtKeyUsage) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// ExpectKeyUsageExtKeyUsageServerAuth checks if the issued certificate has the extended key usage of server auth
func ExpectKeyUsageExtKeyUsageServerAuth(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return err
	}

	if !containsExtKeyUsage(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return fmt.Errorf("Expected certificate to have ExtKeyUsageServerAuth, but got %v", cert.ExtKeyUsage)
	}
	return nil
}

// ExpectKeyUsageExtKeyUsageServerAuth checks if the issued certificate has the extended key usage of client auth
func ExpectKeyUsageExtKeyUsageClientAuth(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return err
	}

	if !containsExtKeyUsage(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return fmt.Errorf("Expected certificate to have ExtKeyUsageClientAuth, but got %v", cert.ExtKeyUsage)
	}
	return nil
}

// ExpectKeyUsageKeyUsageKeyAgreement checks if the issued certificate has the key usage of key agreement
func ExpectKeyUsageKeyUsageKeyAgreement(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return err
	}

	// taking the key usage here and use a binary OR to flip all non KeyUsageKeyAgreement bits to 0
	// so if KeyUsageKeyAgreement the value will be exacty x509.KeyUsageKeyAgreement
	usage := cert.KeyUsage
	usage &= x509.KeyUsageKeyAgreement
	if usage != x509.KeyUsageKeyAgreement {
		return fmt.Errorf("Expected certificate to have KeyUsageKeyAgreement %#b, but got %v %#b", x509.KeyUsageKeyAgreement, usage, usage)
	}

	return nil
}

// ExpectEmailsToMatch check if the issued certificate has all requested email SANs
func ExpectEmailsToMatch(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return err
	}

	if !util.EqualUnsorted(cert.EmailAddresses, certificate.Spec.EmailAddresses) {
		return fmt.Errorf("certificate doesn't contain Email SANs: exp=%v got=%v", certificate.Spec.EmailAddresses, cert.EmailAddresses)
	}

	return nil
}
