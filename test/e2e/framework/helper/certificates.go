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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/bits"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/e2e/framework/log"
)

// WaitForCertificateReady waits for the certificate resource to enter a Ready
// state.
func (h *Helper) WaitForCertificateReady(ns, name string, timeout time.Duration) (*v1alpha2.Certificate, error) {
	var certificate *v1alpha2.Certificate
	err := wait.PollImmediate(time.Second, timeout,
		func() (bool, error) {
			var err error
			log.Logf("Waiting for Certificate %v to be ready", name)
			certificate, err = h.CMClient.CertmanagerV1alpha2().Certificates(ns).Get(name, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("error getting Certificate %v: %v", name, err)
			}
			isReady := apiutil.CertificateHasCondition(certificate, v1alpha2.CertificateCondition{
				Type:   v1alpha2.CertificateConditionReady,
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
func (h *Helper) WaitForCertificateNotReady(ns, name string, timeout time.Duration) (*v1alpha2.Certificate, error) {
	var certificate *v1alpha2.Certificate
	err := wait.PollImmediate(time.Second, timeout,
		func() (bool, error) {
			var err error
			log.Logf("Waiting for Certificate %v to be ready", name)
			certificate, err = h.CMClient.CertmanagerV1alpha2().Certificates(ns).Get(name, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("error getting Certificate %v: %v", name, err)
			}
			isReady := apiutil.CertificateHasCondition(certificate, v1alpha2.CertificateCondition{
				Type:   v1alpha2.CertificateConditionReady,
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
func (h *Helper) ValidateIssuedCertificate(certificate *v1alpha2.Certificate, rootCAPEM []byte) (*x509.Certificate, error) {
	log.Logf("Getting the TLS certificate Secret resource")
	secret, err := h.KubeClient.CoreV1().Secrets(certificate.Namespace).Get(certificate.Spec.SecretName, metav1.GetOptions{})
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
	switch certificate.Spec.KeyAlgorithm {
	case v1alpha2.KeyAlgorithm(""),
		v1alpha2.RSAKeyAlgorithm:
		_, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("Expected private key of type RSA, but it was: %T", key)
		}
	case v1alpha2.ECDSAKeyAlgorithm:
		_, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("Expected private key of type ECDSA, but it was: %T", key)
		}
	default:
		return nil, fmt.Errorf("unrecognised requested private key algorithm %q", certificate.Spec.KeyAlgorithm)
	}

	// TODO: validate private key KeySize

	// check the provided certificate is valid
	expectedOrganization := pki.OrganizationForCertificate(certificate)
	expectedDNSNames := certificate.Spec.DNSNames
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
		if !util.Contains(cert.DNSNames, cert.Subject.CommonName) {
			commonNameCorrect = false
		}
	} else if expectedCN != cert.Subject.CommonName {
		commonNameCorrect = false
	}

	if !commonNameCorrect || !util.Subset(cert.DNSNames, expectedDNSNames) || !util.EqualUnsorted(pki.URLsToString(cert.URIs), expectedURIs) ||
		!(len(cert.Subject.Organization) == 0 || util.EqualUnsorted(cert.Subject.Organization, expectedOrganization)) {
		return nil, fmt.Errorf("Expected certificate valid for CN %q, O %v, dnsNames %v, uriSANs %v,but got a certificate valid for CN %q, O %v, dnsNames %v, uriSANs %v",
			expectedCN, expectedOrganization, expectedDNSNames, expectedURIs, cert.Subject.CommonName, cert.Subject.Organization, cert.DNSNames, cert.URIs)
	}

	if certificate.Status.NotAfter == nil {
		return nil, fmt.Errorf("No certificate expiration found for Certificate %q", certificate.Name)
	}
	if !cert.NotAfter.Equal(certificate.Status.NotAfter.Time) {
		return nil, fmt.Errorf("Expected certificate expiry date to be %v, but got %v", certificate.Status.NotAfter, cert.NotAfter)
	}

	label, ok := secret.Annotations[v1alpha2.CertificateNameKey]
	if !ok {
		return nil, fmt.Errorf("Expected secret to have certificate-name label, but had none")
	}

	if label != certificate.Name {
		return nil, fmt.Errorf("Expected secret to have certificate-name label with a value of %q, but got %q", certificate.Name, label)
	}

	usages := make(map[v1alpha2.KeyUsage]bool)
	for _, u := range certificate.Spec.Usages {
		usages[u] = true
	}
	if certificate.Spec.IsCA {
		if !cert.IsCA {
			return nil, fmt.Errorf("Expected secret to have IsCA set to true, but was false")
		}
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, fmt.Errorf("Expected secret to have x509.KeyUsageCertSign bit set but was not")
		}
		usages[v1alpha2.UsageCertSign] = true
	}

	if len(certificate.Spec.Usages) > 0 {
		sumFoundUsages := bits.OnesCount(uint(cert.KeyUsage)) + len(cert.ExtKeyUsage)
		if len(usages) != sumFoundUsages {
			return nil, fmt.Errorf("Expected secret to have the same sum of KeyUsages and ExtKeyUsages [%d] as the number of Usages [%d] in Certificate", sumFoundUsages, len(usages))
		}
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

func (h *Helper) WaitCertificateIssuedValid(ns, name string, timeout time.Duration) error {
	return h.WaitCertificateIssuedValidTLS(ns, name, timeout, nil)
}

func (h *Helper) WaitCertificateIssuedValidTLS(ns, name string, timeout time.Duration, rootCAPEM []byte) error {
	certificate, err := h.WaitForCertificateReady(ns, name, timeout)
	if err != nil {
		log.Logf("Error waiting for Certificate to become Ready: %v", err)
		h.Kubectl(ns).DescribeResource("certificate", name)
		h.Kubectl(ns).Describe("order", "challenge")
		h.describeCertificateRequestFromCertificate(ns, certificate)
		return err
	}

	_, err = h.ValidateIssuedCertificate(certificate, rootCAPEM)
	if err != nil {
		log.Logf("Error validating issued certificate: %v", err)
		h.Kubectl(ns).DescribeResource("certificate", name)
		h.Kubectl(ns).Describe("order", "challenge")
		h.describeCertificateRequestFromCertificate(ns, certificate)
		return err
	}

	return nil
}

func (h *Helper) describeCertificateRequestFromCertificate(ns string, certificate *v1alpha2.Certificate) {
	if certificate == nil {
		return
	}

	crName, err := apiutil.ComputeCertificateRequestName(certificate)
	if err != nil {
		log.Logf("Failed to compute CertificateRequest name from certificate: %s", err)
		return
	}
	h.Kubectl(ns).DescribeResource("certificaterequest", crName)
}
