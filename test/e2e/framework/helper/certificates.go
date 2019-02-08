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
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/e2e/framework/log"
)

// WaitForCertificateReady waits for the certificate resource to enter a Ready
// state.
func (h *Helper) WaitForCertificateReady(ns, name string, timeout time.Duration) (*v1alpha1.Certificate, error) {
	var certificate *v1alpha1.Certificate
	err := wait.PollImmediate(time.Second, timeout,
		func() (bool, error) {
			var err error
			log.Logf("Waiting for Certificate %v to be ready", name)
			certificate, err = h.CMClient.CertmanagerV1alpha1().Certificates(ns).Get(name, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("error getting Certificate %v: %v", name, err)
			}
			isReady := apiutil.CertificateHasCondition(certificate, v1alpha1.CertificateCondition{
				Type:   v1alpha1.CertificateConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
			if !isReady {
				log.Logf("Expected Certificate to have Ready condition 'true' but it has: %v", certificate.Status.Conditions)
				return false, nil
			}
			return true, nil
		},
	)

	if err != nil {
		return nil, err
	}

	return certificate, nil
}

// WaitForCertificateNotReady waits for the certificate resource to enter a
// non-Ready state.
func (h *Helper) WaitForCertificateNotReady(ns, name string, timeout time.Duration) (*v1alpha1.Certificate, error) {
	var certificate *v1alpha1.Certificate
	err := wait.PollImmediate(time.Second, timeout,
		func() (bool, error) {
			var err error
			log.Logf("Waiting for Certificate %v to be ready", name)
			certificate, err = h.CMClient.CertmanagerV1alpha1().Certificates(ns).Get(name, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("error getting Certificate %v: %v", name, err)
			}
			isReady := apiutil.CertificateHasCondition(certificate, v1alpha1.CertificateCondition{
				Type:   v1alpha1.CertificateConditionReady,
				Status: v1alpha1.ConditionFalse,
			})
			if !isReady {
				log.Logf("Expected Certificate to have Ready condition 'true' but it has: %v", certificate.Status.Conditions)
				return false, nil
			}
			return true, nil
		},
	)

	if err != nil {
		return nil, err
	}

	return certificate, nil
}

// ValidateIssuedCertificate will ensure that the given Certificate has a
// certificate issued for it, and that the details on the x509 certificate are
// correct as defined by the Certificate's spec.
func (h *Helper) ValidateIssuedCertificate(certificate *v1alpha1.Certificate, rootCAPEM []byte) (*x509.Certificate, error) {
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
	case v1alpha1.KeyAlgorithm(""),
		v1alpha1.RSAKeyAlgorithm:
		_, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("Expected private key of type RSA, but it was: %T", key)
		}
	case v1alpha1.ECDSAKeyAlgorithm:
		_, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("Expected private key of type ECDSA, but it was: %T", key)
		}
	default:
		return nil, fmt.Errorf("unrecognised requested private key algorithm %q", certificate.Spec.KeyAlgorithm)
	}

	// TODO: validate private key KeySize

	// check the provided certificate is valid
	expectedCN := pki.CommonNameForCertificate(certificate)
	expectedOrganization := pki.OrganizationForCertificate(certificate)
	expectedDNSNames := pki.DNSNamesForCertificate(certificate)

	certBytes, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		return nil, fmt.Errorf("No certificate data found for Certificate %q (secret %q)", certificate.Name, certificate.Spec.SecretName)
	}

	cert, err := pki.DecodeX509CertificateBytes(certBytes)
	if err != nil {
		return nil, err
	}
	if expectedCN != cert.Subject.CommonName || !util.EqualUnsorted(cert.DNSNames, expectedDNSNames) || !(len(cert.Subject.Organization) == 0 || util.EqualUnsorted(cert.Subject.Organization, expectedOrganization)) {
		return nil, fmt.Errorf("Expected certificate valid for CN %q, O %v, dnsNames %v but got a certificate valid for CN %q, O %v, dnsNames %v", expectedCN, expectedOrganization, expectedDNSNames, cert.Subject.CommonName, cert.Subject.Organization, cert.DNSNames)
	}

	if certificate.Status.NotAfter == nil {
		return nil, fmt.Errorf("No certificate expiration found for Certificate %q", certificate.Name)
	}
	if !cert.NotAfter.Equal(certificate.Status.NotAfter.Time) {
		return nil, fmt.Errorf("Expected certificate expiry date to be %v, but got %v", certificate.Status.NotAfter, cert.NotAfter)
	}

	label, ok := secret.Labels[v1alpha1.CertificateNameKey]
	if !ok {
		return nil, fmt.Errorf("Expected secret to have certificate-name label, but had none")
	}

	if label != certificate.Name {
		return nil, fmt.Errorf("Expected secret to have certificate-name label with a value of %q, but got %q", certificate.Name, label)
	}

	// TODO: move this verification step out of this function
	if rootCAPEM != nil {
		rootCertPool := x509.NewCertPool()
		rootCertPool.AppendCertsFromPEM(rootCAPEM)
		intermediateCertPool := x509.NewCertPool()
		intermediateCertPool.AppendCertsFromPEM(certBytes)
		opts := x509.VerifyOptions{
			DNSName:       expectedDNSNames[0],
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
		return err
	}

	_, err = h.ValidateIssuedCertificate(certificate, rootCAPEM)
	if err != nil {
		log.Logf("Error validating issued certificate: %v", err)
		h.Kubectl(ns).DescribeResource("certificate", name)
		return err
	}

	return nil
}
