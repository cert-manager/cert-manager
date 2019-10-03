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

package helper

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/bits"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/e2e/framework/log"
)

// WaitForCertificateRequestReady waits for the CertificateRequest resource to
// enter a Ready state.
func (h *Helper) WaitForCertificateRequestReady(ns, name string, timeout time.Duration) (*v1alpha2.CertificateRequest, error) {
	var cr *v1alpha2.CertificateRequest
	err := wait.PollImmediate(time.Second, timeout,
		func() (bool, error) {
			var err error
			log.Logf("Waiting for CertificateRequest %s to be ready", name)
			cr, err = h.CMClient.CertmanagerV1alpha2().CertificateRequests(ns).Get(name, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("error getting CertificateRequest %s: %v", name, err)
			}
			isReady := apiutil.CertificateRequestHasCondition(cr, v1alpha2.CertificateRequestCondition{
				Type:   v1alpha2.CertificateRequestConditionReady,
				Status: cmmeta.ConditionTrue,
			})
			if !isReady {
				log.Logf("Expected CertificateReques to have Ready condition 'true' but it has: %v", cr.Status.Conditions)
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
func (h *Helper) ValidateIssuedCertificateRequest(cr *v1alpha2.CertificateRequest, key crypto.Signer, rootCAPEM []byte) (*x509.Certificate, error) {
	csr, err := pki.DecodeX509CertificateRequestBytes(cr.Spec.CSRPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CertificateRequest's Spec.CSRPEM: %s", err)
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

	usages := make(map[v1alpha2.KeyUsage]bool)
	for _, u := range cr.Spec.Usages {
		usages[u] = true
	}
	if cr.Spec.IsCA {
		if !cert.IsCA {
			return nil, fmt.Errorf("Expected csr cert to have IsCA set to true, but was false")
		}
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, fmt.Errorf("Expected csr cert to have x509.KeyUsageCertSign bit set but was not")
		}
		usages[v1alpha2.UsageCertSign] = true
	}

	if len(cr.Spec.Usages) > 0 {
		sumFoundUsages := bits.OnesCount(uint(cert.KeyUsage)) + len(cert.ExtKeyUsage)
		if len(usages) != sumFoundUsages {
			return nil, fmt.Errorf("Expected csr cert to have the same sum of KeyUsages and ExtKeyUsages [%d] as the number of Usages [%d] in Certificate", sumFoundUsages, len(usages))
		}
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
		log.Logf("Error waiting for CertificateReques to become Ready: %v", err)
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
