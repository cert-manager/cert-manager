/*
Copyright 2021 The cert-manager Authors.

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
	"encoding/base64"
	"fmt"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	experimentalapi "github.com/jetstack/cert-manager/pkg/apis/experimental/v1alpha1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	ctrlutil "github.com/jetstack/cert-manager/pkg/controller/certificatesigningrequests/util"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/e2e/framework/log"
)

// WaitForCertificateSigningRequestSigned waits for the
// CertificateSigningRequest resource to be signed.
func (h *Helper) WaitForCertificateSigningRequestSigned(ns, name string, timeout time.Duration) (*certificatesv1.CertificateSigningRequest, error) {
	var csr *certificatesv1.CertificateSigningRequest
	err := wait.PollImmediate(time.Second, timeout,
		func() (bool, error) {
			var err error
			log.Logf("Waiting for CertificateSigningRequest %s to be ready", name)
			csr, err = h.KubeClient.CertificatesV1().CertificateSigningRequests().Get(context.TODO(), name, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("error getting CertificateSigningRequest %s: %v", name, err)
			}
			if len(csr.Status.Certificate) == 0 {
				log.Logf("Expected CertificateSigningRequest to be signed")
				return false, nil
			}
			return true, nil
		},
	)

	if err != nil {
		return nil, err
	}

	return csr, nil
}

// ValidateIssuedCertificateSigningRequest will ensure that the given
// CertificateSigningRequest has a certificate issued for it, and that the
// details on the x509 certificate are correct as defined by the
// CertificateSigningRequest's spec.
func (h *Helper) ValidateIssuedCertificateSigningRequest(kubeCSR *certificatesv1.CertificateSigningRequest, key crypto.Signer, rootCAPEM []byte) (*x509.Certificate, error) {
	csr, err := pki.DecodeX509CertificateRequestBytes(kubeCSR.Spec.Request)
	if err != nil {
		return nil, err
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

	// check the provided certificate is valid
	expectedOrganization := csr.Subject.Organization
	expectedDNSNames := csr.DNSNames
	expectedIPAddresses := csr.IPAddresses
	expectedURIs := csr.URIs

	cert, err := pki.DecodeX509CertificateBytes(kubeCSR.Status.Certificate)
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

	certificateKeyUsages, certificateExtKeyUsages, err := pki.BuildKeyUsagesKube(kubeCSR.Spec.Usages)
	if err != nil {
		return nil, err
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

	signerRef, ok := ctrlutil.SignerIssuerRefFromSignerName(kubeCSR.Spec.SignerName)
	if !ok {
		return nil, fmt.Errorf("failed to build issuer ref from signer name %q", kubeCSR.Spec.SignerName)
	}

	issuerKind, ok := ctrlutil.IssuerKindFromType(signerRef.Type)
	if !ok {
		return nil, fmt.Errorf("issuer type is not recognised %q", signerRef.Type)
	}

	defaultCertKeyUsages, defaultCertExtKeyUsages, err := h.defaultKeyUsagesToAdd(signerRef.Namespace, &cmmeta.ObjectReference{
		Name:  signerRef.Name,
		Kind:  issuerKind,
		Group: signerRef.Group,
	})
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

	kubeCSRCAPEM, err := base64.StdEncoding.DecodeString(kubeCSR.Annotations[experimentalapi.CertificateSigningRequestCAAnnotationKey])
	if err != nil {
		return nil, err
	}

	// TODO: move this verification step out of this function
	if rootCAPEM != nil {
		rootCertPool := x509.NewCertPool()
		rootCertPool.AppendCertsFromPEM(rootCAPEM)
		intermediateCertPool := x509.NewCertPool()
		intermediateCertPool.AppendCertsFromPEM(kubeCSRCAPEM)
		opts := x509.VerifyOptions{
			DNSName:       expectedDNSName,
			Intermediates: intermediateCertPool,
			Roots:         rootCertPool,
		}

		if _, err := cert.Verify(opts); err != nil {
			return nil, err
		}
	}

	if !ctrlutil.CertificateSigningRequestIsApproved(kubeCSR) {
		return nil, fmt.Errorf("CertificateSigningRequest does not have an Approved condition: %+v", kubeCSR.Status.Conditions)
	}
	if ctrlutil.CertificateSigningRequestIsDenied(kubeCSR) {
		return nil, fmt.Errorf("CertificateSigningRequest has a Denied conditon: %+v", kubeCSR.Status.Conditions)
	}

	return cert, nil
}

func (h *Helper) WaitCertificateSigningRequestIssuedValidTLS(ns, name string, timeout time.Duration, key crypto.Signer, rootCAPEM []byte) error {
	csr, err := h.WaitForCertificateSigningRequestSigned(ns, name, timeout)
	if err != nil {
		log.Logf("Error waiting for CertificateSigningRequest to become Ready: %v", err)
		h.Kubectl("").DescribeResource("certificatesigningrequest", name)
		return err
	}

	_, err = h.ValidateIssuedCertificateSigningRequest(csr, key, rootCAPEM)
	if err != nil {
		log.Logf("Error validating issued certificate: %v", err)
		h.Kubectl("").DescribeResource("certificatesigningrequest", name)
		return err
	}

	return nil
}

func (h *Helper) CertificateSigningRequestDurationValid(csr *certificatesv1.CertificateSigningRequest, duration, fuzz time.Duration) error {
	if len(csr.Status.Certificate) == 0 {
		return fmt.Errorf("No certificate data found for CertificateSigningRequest %s", csr.Name)
	}

	cert, err := pki.DecodeX509CertificateBytes(csr.Status.Certificate)
	if err != nil {
		return err
	}
	certDuration := cert.NotAfter.Sub(cert.NotBefore)
	if certDuration > (duration+fuzz) || certDuration < duration {
		return fmt.Errorf("Expected duration of %s, got %s (fuzz: %s) [NotBefore: %s, NotAfter: %s]", duration, certDuration,
			fuzz, cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}

	return nil
}
