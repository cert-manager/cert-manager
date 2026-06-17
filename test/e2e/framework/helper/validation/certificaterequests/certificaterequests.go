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

package certificaterequests

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

// ValidationFunc describes a CertificateRequest validation helper function
type ValidationFunc func(certificaterequest *cmapi.CertificateRequest, key crypto.Signer) error

// ExpectValidCertificate checks if the certificate is a valid x509 certificate
func ExpectValidCertificate(cr *cmapi.CertificateRequest, _ crypto.Signer) error {
	_, err := pki.DecodeX509CertificateBytes(cr.Status.Certificate)
	return err
}

// ExpectCertificateOrganizationToMatch checks if the issued
// certificate has the same Organization as the requested one
func ExpectCertificateOrganizationToMatch(cr *cmapi.CertificateRequest, _ crypto.Signer) error {
	cert, err := pki.DecodeX509CertificateBytes(cr.Status.Certificate)
	if err != nil {
		return err
	}
	req, err := pki.DecodeX509CertificateRequestBytes(cr.Spec.Request)
	if err != nil {
		return err
	}

	expectedOrganization := req.Subject.Organization
	if !util.EqualUnsorted(cert.Subject.Organization, expectedOrganization) {
		return fmt.Errorf("Expected certificate valid for O %v, but got a certificate valid for O %v", expectedOrganization, cert.Subject.Organization)
	}

	return nil
}

// ExpectValidPrivateKeyData checks the requesting private key matches the
// signed certificate
func ExpectValidPrivateKeyData(cr *cmapi.CertificateRequest, key crypto.Signer) error {
	cert, err := pki.DecodeX509CertificateBytes(cr.Status.Certificate)
	if err != nil {
		return err
	}

	equal := func() (bool, error) {
		switch pub := key.Public().(type) {
		case *rsa.PublicKey:
			return pub.Equal(cert.PublicKey), nil
		case *ecdsa.PublicKey:
			return pub.Equal(cert.PublicKey), nil
		case ed25519.PublicKey:
			return pub.Equal(cert.PublicKey), nil
		default:
			return false, fmt.Errorf("Unrecognised public key type: %T", key)
		}
	}

	ok, err := equal()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("Expected signed certificate's public key to match requester's private key")
	}

	return nil
}

// ExpectCertificateDNSNamesToMatch checks if the issued certificate has all
// DNS names it requested, accounting for the CommonName being optionally
// copied to the DNS Names
func ExpectCertificateDNSNamesToMatch(cr *cmapi.CertificateRequest, _ crypto.Signer) error {
	cert, err := pki.DecodeX509CertificateBytes(cr.Status.Certificate)
	if err != nil {
		return err
	}
	req, err := pki.DecodeX509CertificateRequestBytes(cr.Spec.Request)
	if err != nil {
		return err
	}

	if !util.EqualUnsorted(cert.DNSNames, req.DNSNames) &&
		!util.EqualUnsorted(cert.DNSNames, append(req.DNSNames, req.Subject.CommonName)) {
		return fmt.Errorf("Expected certificate valid for DNSNames %v, but got a certificate valid for DNSNames %v", req.DNSNames, cert.DNSNames)
	}

	return nil
}

// ExpectCertificateURIsToMatch checks if the issued certificate
// has all URI SANs names it requested
func ExpectCertificateURIsToMatch(cr *cmapi.CertificateRequest, _ crypto.Signer) error {
	cert, err := pki.DecodeX509CertificateBytes(cr.Status.Certificate)
	if err != nil {
		return err
	}
	req, err := pki.DecodeX509CertificateRequestBytes(cr.Spec.Request)
	if err != nil {
		return err
	}

	actualURIs := pki.URLsToString(cert.URIs)
	expectedURIs := pki.URLsToString(req.URIs)
	if !util.EqualUnsorted(actualURIs, expectedURIs) {
		return fmt.Errorf("Expected certificate valid for URIs %v, but got a certificate valid for URIs %v", expectedURIs, actualURIs)
	}

	return nil
}

// ExpectCertificateIPsToMatch checks if the issued certificate
// has all IP SANs names it requested
func ExpectCertificateIPsToMatch(cr *cmapi.CertificateRequest, _ crypto.Signer) error {
	cert, err := pki.DecodeX509CertificateBytes(cr.Status.Certificate)
	if err != nil {
		return err
	}
	req, err := pki.DecodeX509CertificateRequestBytes(cr.Spec.Request)
	if err != nil {
		return err
	}

	actualIPs := pki.IPAddressesToString(cert.IPAddresses)
	expectedIPs := pki.IPAddressesToString(req.IPAddresses)
	if !util.EqualUnsorted(actualIPs, expectedIPs) {
		return fmt.Errorf("Expected certificate valid for IPs %v, but got a certificate valid for IPs %v", expectedIPs, actualIPs)
	}

	return nil
}

// ExpectValidCommonName checks if the issued certificate has the requested CN or one of the DNS (or IP Address) SANs
func ExpectValidCommonName(cr *cmapi.CertificateRequest, _ crypto.Signer) error {
	cert, err := pki.DecodeX509CertificateBytes(cr.Status.Certificate)
	if err != nil {
		return err
	}
	req, err := pki.DecodeX509CertificateRequestBytes(cr.Spec.Request)
	if err != nil {
		return err
	}

	expectedCN := req.Subject.CommonName

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

// ExpectKeyUsageExtKeyUsageServerAuth checks if the issued certificate has the
// extended key usage of server auth
func ExpectKeyUsageExtKeyUsageServerAuth(cr *cmapi.CertificateRequest, _ crypto.Signer) error {
	cert, err := pki.DecodeX509CertificateBytes(cr.Status.Certificate)
	if err != nil {
		return err
	}

	if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return fmt.Errorf("Expected certificate to have ExtKeyUsageServerAuth, but got %v", cert.ExtKeyUsage)
	}
	return nil
}

// ExpectKeyUsageExtKeyUsageClientAuth checks if the issued certificate has the
// extended key usage of client auth
func ExpectKeyUsageExtKeyUsageClientAuth(cr *cmapi.CertificateRequest, _ crypto.Signer) error {
	cert, err := pki.DecodeX509CertificateBytes(cr.Status.Certificate)
	if err != nil {
		return err
	}

	if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return fmt.Errorf("Expected certificate to have ExtKeyUsageClientAuth, but got %v", cert.ExtKeyUsage)
	}
	return nil
}

// ExpectEmailsToMatch check if the issued certificate has all requested email SANs
func ExpectEmailsToMatch(cr *cmapi.CertificateRequest, _ crypto.Signer) error {
	cert, err := pki.DecodeX509CertificateBytes(cr.Status.Certificate)
	if err != nil {
		return err
	}
	req, err := pki.DecodeX509CertificateRequestBytes(cr.Spec.Request)
	if err != nil {
		return err
	}

	if !util.EqualUnsorted(cert.EmailAddresses, req.EmailAddresses) {
		return fmt.Errorf("certificate doesn't contain Email SANs: exp=%v got=%v", req.EmailAddresses, cert.EmailAddresses)
	}

	return nil
}

// ExpectValidBasicConstraints checks the certificate is a CA if requested
func ExpectValidBasicConstraints(cr *cmapi.CertificateRequest, _ crypto.Signer) error {
	cert, err := pki.DecodeX509CertificateBytes(cr.Status.Certificate)
	if err != nil {
		return err
	}

	if cert.IsCA != cr.Spec.IsCA {
		return fmt.Errorf("requested certificate does not match expected IsCA, exp=%t got=%t",
			cr.Spec.IsCA, cert.IsCA)
	}

	// TODO: also validate pathLen

	return nil
}

// ExpectConditionApproved checks that the CertificateRequest has been
// Approved
func ExpectConditionApproved(cr *cmapi.CertificateRequest, _ crypto.Signer) error {
	if !apiutil.CertificateRequestIsApproved(cr) {
		return fmt.Errorf("CertificateRequest does not have an Approved condition: %v", cr.Status.Conditions)
	}

	return nil
}

// ExpectConditionNotDenied checks that the CertificateRequest has not
// been Denied
func ExpectConditionNotDenied(cr *cmapi.CertificateRequest, _ crypto.Signer) error {
	if apiutil.CertificateRequestIsDenied(cr) {
		return fmt.Errorf("CertificateRequest has a Denied condition: %v", cr.Status.Conditions)
	}

	return nil
}

// ExpectDuration checks if the issued certificate matches the CertificateRequest's duration
func ExpectDurationToMatch(cr *cmapi.CertificateRequest, key crypto.Signer) error {
	certDuration := apiutil.DefaultCertDuration(cr.Spec.Duration)
	return ExpectDuration(certDuration, 30*time.Second)(cr, key)
}

func ExpectDuration(expectedDuration, fuzz time.Duration) func(cr *cmapi.CertificateRequest, key crypto.Signer) error {
	return func(cr *cmapi.CertificateRequest, key crypto.Signer) error {
		certBytes := cr.Status.Certificate
		if len(certBytes) == 0 {
			return fmt.Errorf("no certificate data found in CertificateRequest.Status.Certificate")
		}
		cert, err := pki.DecodeX509CertificateBytes(certBytes)
		if err != nil {
			return err
		}

		// Here we ensure that the requested duration is what is signed on the
		// certificate. We tolerate fuzz either way.
		certDuration := cert.NotAfter.Sub(cert.NotBefore)
		if certDuration > (expectedDuration+fuzz) || certDuration < (expectedDuration-fuzz) {
			return fmt.Errorf(
				"expected duration of %s, got %s (fuzz: %s) [NotBefore: %s, NotAfter: %s]",
				expectedDuration, certDuration, fuzz,
				cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339),
			)
		}

		return nil
	}
}
