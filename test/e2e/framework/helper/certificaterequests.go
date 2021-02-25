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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/e2e/framework/log"
)

// WaitForCertificateRequestReady waits for the CertificateRequest resource to
// enter a Ready state.
func (h *Helper) WaitForCertificateRequestReady(ns, name string, timeout time.Duration) (*cmapi.CertificateRequest, error) {
	var cr *cmapi.CertificateRequest
	err := wait.PollImmediate(time.Second, timeout,
		func() (bool, error) {
			var err error
			log.Logf("Waiting for CertificateRequest %s to be ready", name)
			cr, err = h.CMClient.CertmanagerV1().CertificateRequests(ns).Get(context.TODO(), name, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("error getting CertificateRequest %s: %v", name, err)
			}
			isReady := apiutil.CertificateRequestHasCondition(cr, cmapi.CertificateRequestCondition{
				Type:   cmapi.CertificateRequestConditionReady,
				Status: cmmeta.ConditionTrue,
			})
			if !isReady {
				log.Logf("Expected CertificateRequest to have Ready condition 'true' but it has: %v", cr.Status.Conditions)
				return false, nil
			}
			return true, nil
		},
	)

	if err != nil {
		return nil, err
	}

	return cr, nil
}

// ValidateIssuedCertificateRequest will ensure that the given
// CertificateRequest has a certificate issued for it, and that the details on
// the x509 certificate are correct as defined by the CertificateRequest's
// spec.
func (h *Helper) ValidateIssuedCertificateRequest(cr *cmapi.CertificateRequest, key crypto.Signer, rootCAPEM []byte) (*x509.Certificate, error) {
	csr, err := pki.DecodeX509CertificateRequestBytes(cr.Spec.Request)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CertificateRequest's Spec.Request: %s", err)
	}

	// validate private key is of the correct type (rsa or ecdsa)
	switch csr.PublicKeyAlgorithm {
	case x509.RSA:
		_, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("Expected private key of type RSA, but it was: %T", key)
		}
	case x509.ECDSA:
		_, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("Expected private key of type ECDSA, but it was: %T", key)
		}
	default:
		return nil, fmt.Errorf("unrecognised requested private key algorithm %q", csr.PublicKeyAlgorithm)
	}

	// TODO: validate private key KeySize

	// check the provided certificate is valid
	expectedOrganization := csr.Subject.Organization
	expectedDNSNames := csr.DNSNames
	expectedIPAddresses := csr.IPAddresses
	expectedURIs := csr.URIs

	cert, err := pki.DecodeX509CertificateBytes(cr.Status.Certificate)
	if err != nil {
		return nil, err
	}

	commonNameCorrect := true
	expectedCN := csr.Subject.CommonName
	if len(expectedCN) == 0 && len(cert.Subject.CommonName) > 0 {
		if !util.Contains(cert.DNSNames, cert.Subject.CommonName) {
			commonNameCorrect = false
		}
	} else if expectedCN != cert.Subject.CommonName {
		commonNameCorrect = false
	}

	if !commonNameCorrect ||
		!util.EqualUnsorted(cert.DNSNames, expectedDNSNames) ||
		!util.EqualUnsorted(cert.Subject.Organization, expectedOrganization) ||
		!util.EqualIPsUnsorted(cert.IPAddresses, expectedIPAddresses) ||
		!util.EqualURLsUnsorted(cert.URIs, expectedURIs) {
		return nil, fmt.Errorf("Expected certificate valid for CN %q, O %v, dnsNames %v, IPs %v, URIs %v but got a certificate valid for CN %q, O %v, dnsNames %v, IPs %v URIs %v",
			expectedCN, expectedOrganization, expectedDNSNames, expectedIPAddresses, expectedURIs,
			cert.Subject.CommonName, cert.Subject.Organization, cert.DNSNames, cert.IPAddresses, cert.URIs)
	}

	var expectedDNSName string
	if len(expectedDNSNames) > 0 {
		expectedDNSName = expectedDNSNames[0]
	}

	certificateKeyUsages, certificateExtKeyUsages, err := pki.BuildKeyUsages(cr.Spec.Usages, cr.Spec.IsCA)
	if err != nil {
		return nil, fmt.Errorf("failed to build key usages from certificate: %s", err)
	}

	var keyAlg cmapi.PrivateKeyAlgorithm
	switch csr.PublicKeyAlgorithm {
	case x509.RSA:
		keyAlg = cmapi.RSAKeyAlgorithm
	case x509.ECDSA:
		keyAlg = cmapi.ECDSAKeyAlgorithm
	default:
		return nil, fmt.Errorf("unsupported key algorithm type: %s", csr.PublicKeyAlgorithm)
	}

	defaultCertKeyUsages, defaultCertExtKeyUsages, err := h.defaultKeyUsagesToAdd(cr.Namespace, &cr.Spec.IssuerRef)
	if err != nil {
		return nil, err
	}

	certificateKeyUsages |= defaultCertKeyUsages
	certificateExtKeyUsages = append(certificateExtKeyUsages, defaultCertExtKeyUsages...)

	certificateExtKeyUsages = h.deduplicateExtKeyUsages(certificateExtKeyUsages)

	// If using ECDSA then ignore key encipherment
	if keyAlg == cmapi.ECDSAKeyAlgorithm {
		certificateKeyUsages &^= x509.KeyUsageKeyEncipherment
		cert.KeyUsage &^= x509.KeyUsageKeyEncipherment
	}

	if !h.keyUsagesMatch(cert.KeyUsage, cert.ExtKeyUsage,
		certificateKeyUsages, certificateExtKeyUsages) {
		return nil, fmt.Errorf("key usages and extended key usages do not match: exp=%s got=%s exp=%s got=%s",
			apiutil.KeyUsageStrings(certificateKeyUsages), apiutil.KeyUsageStrings(cert.KeyUsage),
			apiutil.ExtKeyUsageStrings(certificateExtKeyUsages), apiutil.ExtKeyUsageStrings(cert.ExtKeyUsage))
	}

	// TODO: move this verification step out of this function
	if rootCAPEM != nil {
		rootCertPool := x509.NewCertPool()
		rootCertPool.AppendCertsFromPEM(rootCAPEM)
		intermediateCertPool := x509.NewCertPool()
		intermediateCertPool.AppendCertsFromPEM(cr.Status.CA)
		opts := x509.VerifyOptions{
			DNSName:       expectedDNSName,
			Intermediates: intermediateCertPool,
			Roots:         rootCertPool,
		}

		if _, err := cert.Verify(opts); err != nil {
			return nil, err
		}
	}

	return cert, nil
}

func (h *Helper) WaitCertificateRequestIssuedValid(ns, name string, timeout time.Duration, key crypto.Signer) error {
	return h.WaitCertificateRequestIssuedValidTLS(ns, name, timeout, key, nil)
}

func (h *Helper) WaitCertificateRequestIssuedValidTLS(ns, name string, timeout time.Duration, key crypto.Signer, rootCAPEM []byte) error {
	cr, err := h.WaitForCertificateRequestReady(ns, name, timeout)
	if err != nil {
		log.Logf("Error waiting for CertificateRequest to become Ready: %v", err)
		h.Kubectl(ns).DescribeResource("certificaterequest", name)
		h.Kubectl(ns).Describe("order", "challenge")
		return err
	}

	_, err = h.ValidateIssuedCertificateRequest(cr, key, rootCAPEM)
	if err != nil {
		log.Logf("Error validating issued certificate: %v", err)
		h.Kubectl(ns).DescribeResource("certificaterequest", name)
		h.Kubectl(ns).Describe("order", "challenge")
		return err
	}

	return nil
}
