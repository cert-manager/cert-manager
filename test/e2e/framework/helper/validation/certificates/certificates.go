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

package certificates

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"

	"github.com/kr/pretty"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

// ValidationFunc describes a Certificate validation helper function
type ValidationFunc func(certificate *cmapi.Certificate, secret *corev1.Secret) error

// ExpectValidKeysInSecret checks that the secret contains valid keys
func ExpectValidKeysInSecret(_ *cmapi.Certificate, secret *corev1.Secret) error {
	validKeys := []string{corev1.TLSPrivateKeyKey, corev1.TLSCertKey, cmmeta.TLSCAKey, cmapi.CertificateOutputFormatDERKey, cmapi.CertificateOutputFormatCombinedPEMKey}
	nbValidKeys := 0
	for k := range secret.Data {
		for _, k2 := range validKeys {
			if k == k2 {
				nbValidKeys++
				break
			}
		}
	}
	if nbValidKeys < 2 {
		return fmt.Errorf("Expected at least 2 valid keys in certificate secret, but there was %d", nbValidKeys)
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

	// validate private key is of the correct type (rsa, ed25519 or ecdsa)
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
		case cmapi.Ed25519KeyAlgorithm:
			_, ok := key.(ed25519.PrivateKey)
			if !ok {
				return fmt.Errorf("Expected private key of type Ed25519, but it was: %T", key)
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

	var expectedOrganization []string
	if certificate.Spec.Subject != nil {
		expectedOrganization = certificate.Spec.Subject.Organizations
	}
	if certificate.Spec.LiteralSubject != "" {
		sequence, err := pki.UnmarshalSubjectStringToRDNSequence(certificate.Spec.LiteralSubject)
		if err != nil {
			return err
		}

		for _, rdns := range sequence {
			for _, atv := range rdns {
				if atv.Type.Equal(pki.OIDConstants.Organization) {
					if str, ok := atv.Value.(string); ok {
						expectedOrganization = append(expectedOrganization, str)
					}
				}
			}
		}
	}

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

	x509DNSNames := sets.New(cert.DNSNames...)
	expectedDNSNames := sets.New(certificate.Spec.DNSNames...)
	if !x509DNSNames.IsSuperset(expectedDNSNames) {
		return fmt.Errorf("Expected certificate valid for DNSNames %v, but got a certificate valid for DNSNames %v", sets.List(expectedDNSNames), sets.List(x509DNSNames))
	}

	return nil
}

// ExpectCertificateURIsToMatch checks if the issued certificate has all URI SANs names it requested
func ExpectCertificateURIsToMatch(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return err
	}

	actualURIs := pki.URLsToString(cert.URIs)
	expectedURIs := certificate.Spec.URIs
	if !util.EqualUnsorted(actualURIs, expectedURIs) {
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
		// no CN is specified but our CA set one, checking if it is one of our DNS names or IP Addresses
		if !slices.Contains(cert.DNSNames, cert.Subject.CommonName) && !slices.Contains(pki.IPAddressesToString(cert.IPAddresses), cert.Subject.CommonName) {
			return fmt.Errorf("Expected a common name for one of our DNSNames %v or IP Addresses %v, but got a CN of %v", cert.DNSNames, pki.IPAddressesToString(cert.IPAddresses), cert.Subject.CommonName)
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

// ExpectKeyUsageExtKeyUsageServerAuth checks if the issued certificate has the extended key usage of server auth
func ExpectKeyUsageExtKeyUsageServerAuth(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return err
	}

	if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return fmt.Errorf("Expected certificate to have ExtKeyUsageServerAuth, but got %v", cert.ExtKeyUsage)
	}
	return nil
}

// ExpectKeyUsageExtKeyUsageClientAuth checks if the issued certificate has the extended key usage of client auth
func ExpectKeyUsageExtKeyUsageClientAuth(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return err
	}

	if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return fmt.Errorf("Expected certificate to have ExtKeyUsageClientAuth, but got %v", cert.ExtKeyUsage)
	}
	return nil
}

// UsageDigitalSignature checks if a cert has the KeyUsageDigitalSignature key usage set
func ExpectKeyUsageUsageDigitalSignature(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return err
	}

	// taking the key usage here and use a binary OR to flip all non KeyUsageCertSign bits to 0
	// so if KeyUsageCertSign the value will be exactly x509.KeyUsageCertSign
	usage := cert.KeyUsage
	usage &= x509.KeyUsageDigitalSignature
	if usage != x509.KeyUsageDigitalSignature {
		return fmt.Errorf("Expected certificate to have KeyUsageDigitalSignature %#b, but got %v %#b", x509.KeyUsageDigitalSignature, usage, usage)
	}

	return nil
}

// ExpectKeyUsageUsageDataEncipherment checks if a cert has the KeyUsageDataEncipherment key usage set
func ExpectKeyUsageUsageDataEncipherment(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return err
	}

	// taking the key usage here and use a binary OR to flip all non KeyUsageDataEncipherment bits to 0
	// so if KeyUsageDataEncipherment the value will be exactly x509.KeyUsageDataEncipherment
	usage := cert.KeyUsage
	usage &= x509.KeyUsageDataEncipherment
	if usage != x509.KeyUsageDataEncipherment {
		return fmt.Errorf("Expected certificate to have KeyUsageDataEncipherment %#b, but got %v %#b", x509.KeyUsageDataEncipherment, usage, usage)
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

// ExpectCorrectTrustChain checks if the cert is signed by the root CA if one is provided
func ExpectCorrectTrustChain(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return err
	}

	var dnsName string
	if len(certificate.Spec.DNSNames) > 0 {
		dnsName = certificate.Spec.DNSNames[0]
	}

	rootCertPool := x509.NewCertPool()
	rootCertPool.AppendCertsFromPEM(secret.Data[cmmeta.TLSCAKey])
	intermediateCertPool := x509.NewCertPool()
	intermediateCertPool.AppendCertsFromPEM(secret.Data[corev1.TLSCertKey])
	opts := x509.VerifyOptions{
		DNSName:       dnsName,
		Intermediates: intermediateCertPool,
		Roots:         rootCertPool,
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf(
			"verify error. CERT:\n%s\nROOTS\n%s\nINTERMEDIATES\n%v\nERROR\n%s\n",
			pretty.Sprint(cert),
			pretty.Sprint(rootCertPool),
			pretty.Sprint(intermediateCertPool),
			err,
		)
	}

	return nil
}

// ExpectCARootCertificate checks if the CA cert is root CA if one is provided
func ExpectCARootCertificate(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	caCert, err := pki.DecodeX509CertificateBytes(secret.Data[cmmeta.TLSCAKey])
	if err != nil {
		return err
	}
	if !bytes.Equal(caCert.RawSubject, caCert.RawIssuer) {
		return fmt.Errorf("expected CA certificate to be root CA; want Issuer %v, but got %v", caCert.Subject, caCert.Issuer)
	}

	return nil
}

// ExpectConditionReadyObservedGeneration checks that the ObservedGeneration
// field on the Ready condition which must be true, is set to the Generation of
// the Certificate.
func ExpectConditionReadyObservedGeneration(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	cond := apiutil.GetCertificateCondition(certificate, cmapi.CertificateConditionReady)

	if cond.Status != cmmeta.ConditionTrue || cond.ObservedGeneration != certificate.Generation {
		return fmt.Errorf("expected Certificate to have ready condition true, observedGeneration matching the Certificate generation, got=%+v",
			cond)
	}

	return nil
}

// ExpectValidBasicConstraints asserts that basicConstraints are set correctly on issued certificates
func ExpectValidBasicConstraints(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return err
	}

	if certificate.Spec.IsCA != cert.IsCA {
		return fmt.Errorf("Expected CA basicConstraint to be %v, but got %v", certificate.Spec.IsCA, cert.IsCA)
	}

	// TODO: also validate pathLen

	return nil
}

// ExpectValidAdditionalOutputFormats assert that if additional output formats are requested
// It contains the additional output format keys in the secret and the content are valid.
func ExpectValidAdditionalOutputFormats(certificate *cmapi.Certificate, secret *corev1.Secret) error {
	if len(certificate.Spec.AdditionalOutputFormats) > 0 {
		for _, f := range certificate.Spec.AdditionalOutputFormats {
			switch f.Type {
			case cmapi.CertificateOutputFormatDER:
				if derKey, ok := secret.Data[cmapi.CertificateOutputFormatDERKey]; ok {
					privateKey := secret.Data[corev1.TLSPrivateKeyKey]
					block, _ := pem.Decode(privateKey)
					if !bytes.Equal(derKey, block.Bytes) {
						return fmt.Errorf("expected additional output Format DER %s to contain the binary formatted private Key", cmapi.CertificateOutputFormatDERKey)
					}
				} else {
					return fmt.Errorf("expected additional output format DER key %s to be present in secret", cmapi.CertificateOutputFormatDERKey)
				}
			case cmapi.CertificateOutputFormatCombinedPEM:
				if combinedPem, ok := secret.Data[cmapi.CertificateOutputFormatCombinedPEMKey]; ok {
					privateKey := secret.Data[corev1.TLSPrivateKeyKey]
					certificate := secret.Data[corev1.TLSCertKey]
					expectedCombinedPem := []byte(strings.Join([]string{string(privateKey), string(certificate)}, "\n"))
					if !bytes.Equal(combinedPem, expectedCombinedPem) {
						return fmt.Errorf("expected additional output format CombinedPEM %s to contain the combination of privateKey and certificate", cmapi.CertificateOutputFormatCombinedPEMKey)
					}
				} else {
					return fmt.Errorf("expected additional output format CombinedPEM key %s to be present in secret", cmapi.CertificateOutputFormatCombinedPEMKey)
				}

			default:
				return fmt.Errorf("unknown additional output format %s", f.Type)
			}
		}
	}

	return nil
}
