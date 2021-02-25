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

package helper

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/e2e/framework/log"
)

// WaitForCertificateReady waits for the certificate resource to enter a Ready
// state.
func (h *Helper) WaitForCertificateReady(ns, name string, timeout time.Duration) (*cmapi.Certificate, error) {
	var certificate *cmapi.Certificate
	err := wait.PollImmediate(time.Second, timeout,
		func() (bool, error) {
			var err error
			log.Logf("Waiting for Certificate %v to be ready", name)
			certificate, err = h.CMClient.CertmanagerV1().Certificates(ns).Get(context.TODO(), name, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("error getting Certificate %v: %v", name, err)
			}
			isReady := apiutil.CertificateHasCondition(certificate, cmapi.CertificateCondition{
				Type:   cmapi.CertificateConditionReady,
				Status: cmmeta.ConditionTrue,
			})
			if !isReady {
				log.Logf("Expected Certificate to have Ready condition 'true' but it has: %v", certificate.Status.Conditions)
				return false, nil
			}
			return true, nil
		},
	)

	// return certificate even when error to use for debugging
	return certificate, err
}

// WaitForCertificateNotReady waits for the certificate resource to enter a
// non-Ready state.
func (h *Helper) WaitForCertificateNotReady(ns, name string, timeout time.Duration) (*cmapi.Certificate, error) {
	var certificate *cmapi.Certificate
	err := wait.PollImmediate(time.Second, timeout,
		func() (bool, error) {
			var err error
			log.Logf("Waiting for Certificate %v to be ready", name)
			certificate, err = h.CMClient.CertmanagerV1().Certificates(ns).Get(context.TODO(), name, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("error getting Certificate %v: %v", name, err)
			}
			isReady := apiutil.CertificateHasCondition(certificate, cmapi.CertificateCondition{
				Type:   cmapi.CertificateConditionReady,
				Status: cmmeta.ConditionFalse,
			})
			if !isReady {
				log.Logf("Expected Certificate to have Ready condition 'true' but it has: %v", certificate.Status.Conditions)
				return false, nil
			}
			return true, nil
		},
	)

	// return certificate even when error to use for debugging
	return certificate, err
}

// ValidateIssuedCertificate will ensure that the given Certificate has a
// certificate issued for it, and that the details on the x509 certificate are
// correct as defined by the Certificate's spec.
func (h *Helper) ValidateIssuedCertificate(certificate *cmapi.Certificate, rootCAPEM []byte) (*x509.Certificate, error) {
	log.Logf("Getting the TLS certificate Secret resource")
	secret, err := h.KubeClient.CoreV1().Secrets(certificate.Namespace).Get(context.TODO(), certificate.Spec.SecretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if !(len(secret.Data) == 2 || len(secret.Data) == 3) {
		return nil, fmt.Errorf("Expected 2 keys in certificate secret, but there was %d", len(secret.Data))
	}

	keyBytes, ok := secret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		return nil, fmt.Errorf("No private key data found for Certificate %q (secret %q)", certificate.Name, certificate.Spec.SecretName)
	}
	key, err := pki.DecodePrivateKeyBytes(keyBytes)
	if err != nil {
		return nil, err
	}

	// validate private key is of the correct type (rsa or ecdsa)
	privateKey := certificate.Spec.PrivateKey
	if privateKey == nil {
		privateKey = &cmapi.CertificatePrivateKey{}
	}
	switch privateKey.Algorithm {
	case cmapi.PrivateKeyAlgorithm(""),
		cmapi.RSAKeyAlgorithm:
		_, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("Expected private key of type RSA, but it was: %T", key)
		}
	case cmapi.ECDSAKeyAlgorithm:
		_, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("Expected private key of type ECDSA, but it was: %T", key)
		}
	default:
		return nil, fmt.Errorf("unrecognised requested private key algorithm %q", certificate.Spec.PrivateKey.Algorithm)
	}

	// TODO: validate private key KeySize

	// check the provided certificate is valid
	expectedOrganization := pki.OrganizationForCertificate(certificate)
	expectedDNSNames := certificate.Spec.DNSNames
	expectedIPAddresses := certificate.Spec.IPAddresses
	uris, err := pki.URIsForCertificate(certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URIs: %s", err)
	}

	expectedURIs := pki.URLsToString(uris)

	certBytes, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		return nil, fmt.Errorf("No certificate data found for Certificate %q (secret %q)", certificate.Name, certificate.Spec.SecretName)
	}

	cert, err := pki.DecodeX509CertificateBytes(certBytes)
	if err != nil {
		return nil, err
	}

	commonNameCorrect := true
	expectedCN := certificate.Spec.CommonName
	if len(expectedCN) == 0 && len(cert.Subject.CommonName) > 0 {
		// issuers might set an IP or DNSName as CN
		if !util.Contains(cert.DNSNames, cert.Subject.CommonName) && !util.Contains(pki.IPAddressesToString(cert.IPAddresses), cert.Subject.CommonName) {
			commonNameCorrect = false
		}
	} else if expectedCN != cert.Subject.CommonName {
		commonNameCorrect = false
	}

	if !commonNameCorrect || !util.Subset(cert.DNSNames, expectedDNSNames) || !util.EqualUnsorted(pki.URLsToString(cert.URIs), expectedURIs) ||
		!util.Subset(pki.IPAddressesToString(cert.IPAddresses), expectedIPAddresses) ||
		!(len(cert.Subject.Organization) == 0 || util.EqualUnsorted(cert.Subject.Organization, expectedOrganization)) {
		return nil, fmt.Errorf("Expected certificate valid for CN %q, O %v, dnsNames %v, uriSANs %v,but got a certificate valid for CN %q, O %v, dnsNames %v, uriSANs %v, ipAddresses %v",
			expectedCN, expectedOrganization, expectedDNSNames, expectedURIs, cert.Subject.CommonName, cert.Subject.Organization, cert.DNSNames, cert.URIs, cert.IPAddresses)
	}

	if certificate.Status.NotAfter == nil {
		return nil, fmt.Errorf("No certificate expiration found for Certificate %q", certificate.Name)
	}
	if !cert.NotAfter.Equal(certificate.Status.NotAfter.Time) {
		return nil, fmt.Errorf("Expected certificate expiry date to be %v, but got %v", certificate.Status.NotAfter, cert.NotAfter)
	}

	label, ok := secret.Annotations[cmapi.CertificateNameKey]
	if !ok {
		return nil, fmt.Errorf("Expected secret to have certificate-name label, but had none")
	}

	if label != certificate.Name {
		return nil, fmt.Errorf("Expected secret to have certificate-name label with a value of %q, but got %q", certificate.Name, label)
	}

	certificateKeyUsages, certificateExtKeyUsages, err := pki.BuildKeyUsages(certificate.Spec.Usages, certificate.Spec.IsCA)
	if err != nil {
		return nil, fmt.Errorf("failed to build key usages from certificate: %s", err)
	}

	defaultCertKeyUsages, defaultCertExtKeyUsages, err := h.defaultKeyUsagesToAdd(certificate.Namespace, &certificate.Spec.IssuerRef)
	if err != nil {
		return nil, err
	}

	certificateKeyUsages |= defaultCertKeyUsages
	certificateExtKeyUsages = append(certificateExtKeyUsages, defaultCertExtKeyUsages...)

	// If using ECDSA then ignore key encipherment
	if certificate.Spec.PrivateKey != nil && certificate.Spec.PrivateKey.Algorithm == cmapi.ECDSAKeyAlgorithm {
		certificateKeyUsages &^= x509.KeyUsageKeyEncipherment
		cert.KeyUsage &^= x509.KeyUsageKeyEncipherment
	}

	certificateExtKeyUsages = h.deduplicateExtKeyUsages(certificateExtKeyUsages)

	if !h.keyUsagesMatch(cert.KeyUsage, cert.ExtKeyUsage,
		certificateKeyUsages, certificateExtKeyUsages) {
		return nil, fmt.Errorf("key usages and extended key usages do not match: exp=%s got=%s exp=%s got=%s",
			apiutil.KeyUsageStrings(certificateKeyUsages), apiutil.KeyUsageStrings(cert.KeyUsage),
			apiutil.ExtKeyUsageStrings(certificateExtKeyUsages), apiutil.ExtKeyUsageStrings(cert.ExtKeyUsage))
	}

	if !util.EqualUnsorted(cert.EmailAddresses, certificate.Spec.EmailAddresses) {
		return nil, fmt.Errorf("certificate doesn't contain Email SANs: exp=%v got=%v", certificate.Spec.EmailAddresses, cert.EmailAddresses)
	}

	var dnsName string
	if len(expectedDNSNames) > 0 {
		dnsName = expectedDNSNames[0]
	}

	// TODO: move this verification step out of this function
	if rootCAPEM != nil {
		rootCertPool := x509.NewCertPool()
		rootCertPool.AppendCertsFromPEM(rootCAPEM)
		intermediateCertPool := x509.NewCertPool()
		intermediateCertPool.AppendCertsFromPEM(certBytes)
		opts := x509.VerifyOptions{
			DNSName:       dnsName,
			Intermediates: intermediateCertPool,
			Roots:         rootCertPool,
		}

		if _, err := cert.Verify(opts); err != nil {
			return nil, err
		}
	}

	return cert, nil
}

func (h *Helper) deduplicateExtKeyUsages(us []x509.ExtKeyUsage) []x509.ExtKeyUsage {
	extKeyUsagesMap := make(map[x509.ExtKeyUsage]bool)
	for _, e := range us {
		extKeyUsagesMap[e] = true
	}

	us = make([]x509.ExtKeyUsage, 0)
	for e, ok := range extKeyUsagesMap {
		if ok {
			us = append(us, e)
		}
	}

	return us
}

func (h *Helper) WaitCertificateIssued(ns, name string, timeout time.Duration) error {
	certificate, err := h.WaitForCertificateReady(ns, name, timeout)
	if err != nil {
		log.Logf("Error waiting for Certificate to become Ready: %v", err)
		h.Kubectl(ns).DescribeResource("certificate", name)
		h.Kubectl(ns).Describe("order", "challenge")
		h.describeCertificateRequestFromCertificate(ns, certificate)
	}
	return err
}

func (h *Helper) defaultKeyUsagesToAdd(ns string, issuerRef *cmmeta.ObjectReference) (x509.KeyUsage, []x509.ExtKeyUsage, error) {
	var issuerSpec *cmapi.IssuerSpec
	switch issuerRef.Kind {
	case "ClusterIssuer":
		issuerObj, err := h.CMClient.CertmanagerV1().ClusterIssuers().Get(context.TODO(), issuerRef.Name, metav1.GetOptions{})
		if err != nil {
			return 0, nil, fmt.Errorf("failed to find referenced ClusterIssuer %v: %s",
				issuerRef, err)
		}

		issuerSpec = &issuerObj.Spec
	default:
		issuerObj, err := h.CMClient.CertmanagerV1().Issuers(ns).Get(context.TODO(), issuerRef.Name, metav1.GetOptions{})
		if err != nil {
			return 0, nil, fmt.Errorf("failed to find referenced Issuer %v: %s",
				issuerRef, err)
		}

		issuerSpec = &issuerObj.Spec
	}

	var keyUsages x509.KeyUsage
	var extKeyUsages []x509.ExtKeyUsage

	// Vault and ACME issuers will add server auth and client auth extended key
	// usages by default so we need to add them to the list of expected usages
	if issuerSpec.ACME != nil || issuerSpec.Vault != nil {
		extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	}

	// Vault issuers will add key agreement key usage
	if issuerSpec.Vault != nil {
		keyUsages |= x509.KeyUsageKeyAgreement
	}

	// Venafi issue adds server auth key usage
	if issuerSpec.Venafi != nil {
		extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageServerAuth)
	}

	return keyUsages, extKeyUsages, nil
}

func (h *Helper) keyUsagesMatch(aKU x509.KeyUsage, aEKU []x509.ExtKeyUsage,
	bKU x509.KeyUsage, bEKU []x509.ExtKeyUsage) bool {
	if aKU != bKU {
		return false
	}

	if len(aEKU) != len(bEKU) {
		return false
	}

	sort.SliceStable(aEKU, func(i, j int) bool {
		return aEKU[i] < aEKU[j]
	})

	sort.SliceStable(bEKU, func(i, j int) bool {
		return bEKU[i] < bEKU[j]
	})

	for i := range aEKU {
		if aEKU[i] != bEKU[i] {
			return false
		}
	}

	return true
}

func (h *Helper) describeCertificateRequestFromCertificate(ns string, certificate *cmapi.Certificate) {
	if certificate == nil {
		return
	}

	crName, err := apiutil.ComputeName(certificate.Name, certificate.Spec)
	if err != nil {
		log.Logf("Failed to compute CertificateRequest name from certificate: %s", err)
		return
	}
	h.Kubectl(ns).DescribeResource("certificaterequest", crName)
}
