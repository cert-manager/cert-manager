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
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/validation/certificaterequests"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/log"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

// ErrCertificateRequestFailed is returned when the CertificateRequest has Ready condition False
var ErrCertificateRequestFailed = errors.New("CertificateRequest failed; it has Ready status False and reason Failed")

// WaitForCertificateRequestReady waits for the CertificateRequest resource to
// enter a Ready state.
func (h *Helper) WaitForCertificateRequestReady(ctx context.Context, ns, name string, timeout time.Duration) (*cmapi.CertificateRequest, error) {
	var cr *cmapi.CertificateRequest
	logf, done := log.LogBackoff()
	defer done()
	err := wait.PollUntilContextTimeout(ctx, time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		var err error
		logf("Waiting for CertificateRequest %s to be ready", name)
		cr, err = h.CMClient.CertmanagerV1().CertificateRequests(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("error getting CertificateRequest %s: %v", name, err)
		}

		readyCondition := apiutil.GetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady)
		switch {
		case readyCondition == nil:
			logf(
				"Expected CertificateRequest to have Ready condition 'true' but the Ready condition was not present: %v",
				cr.Status.Conditions,
			)
			return false, nil
		case readyCondition.Status == cmmeta.ConditionUnknown:
			logf("Expected CertificateRequest to have Ready condition 'true' but it has: %v", cr.Status.Conditions)
			return false, nil
		case readyCondition.Status == cmmeta.ConditionFalse:
			if readyCondition.Reason == cmapi.CertificateRequestReasonFailed {
				return true, fmt.Errorf("%w: %v", ErrCertificateRequestFailed, readyCondition)
			}
			logf("Expected CertificateRequest to have Ready condition 'true' but it has: %v", cr.Status.Conditions)
			return false, nil
		}
		return true, nil
	})
	return cr, err
}

// ValidateIssuedCertificateRequest will ensure that the given
// CertificateRequest has a certificate issued for it, and that the details on
// the x509 certificate are correct as defined by the CertificateRequest's
// spec.
func (h *Helper) ValidateIssuedCertificateRequest(ctx context.Context, cr *cmapi.CertificateRequest, key crypto.Signer) (*x509.Certificate, error) {
	csr, err := pki.DecodeX509CertificateRequestBytes(cr.Spec.Request)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CertificateRequest's Spec.Request: %s", err)
	}

	var issuerSpec *cmapi.IssuerSpec
	switch issuerRef := cr.Spec.IssuerRef; issuerRef.Kind {
	case "ClusterIssuer":
		issuerObj, err := h.CMClient.CertmanagerV1().ClusterIssuers().Get(ctx, issuerRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to find referenced ClusterIssuer %v: %s",
				issuerRef, err)
		}

		issuerSpec = &issuerObj.Spec
	default:
		issuerObj, err := h.CMClient.CertmanagerV1().Issuers(cr.Namespace).Get(ctx, issuerRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to find referenced Issuer %v: %s",
				issuerRef, err)
		}

		issuerSpec = &issuerObj.Spec
	}

	if err := certificaterequests.ExpectValidPrivateKeyData(cr, key); err != nil {
		return nil, err
	}

	cert, err := pki.DecodeX509CertificateBytes(cr.Status.Certificate)
	if err != nil {
		return nil, err
	}

	// Verify CN
	{
		commonNameCorrect := true
		expectedCN := csr.Subject.CommonName
		// Do not verify the CN when using an ACME issuer with the ACME test
		// server "Pebble", because Pebble ignores the requested CN and it does
		// not currently allow us to simulate the Lets Encrypt behavior of
		// "promoting" the first DNS name to CN. See:
		// - https://github.com/letsencrypt/pebble/pull/491
		if issuerSpec.ACME != nil && strings.Contains(issuerSpec.ACME.Server, "pebble") {
			expectedCN = ""
		}
		// Some issuers such as Let's Encrypt, "promote" one of the DNS names as
		// the CN if a specific CN has not been requested. See:
		// - https://community.letsencrypt.org/t/is-common-name-automatically-included-in-san/214002
		if len(expectedCN) == 0 && len(cert.Subject.CommonName) > 0 {
			if !slices.Contains(cert.DNSNames, cert.Subject.CommonName) {
				commonNameCorrect = false
			}
		} else if expectedCN != cert.Subject.CommonName {
			commonNameCorrect = false
		}
		if !commonNameCorrect {
			return nil, fmt.Errorf("Expected certificate valid for CN %q but got a certificate valid for CN %q", expectedCN, cert.Subject.CommonName)
		}
	}

	if err := certificaterequests.ExpectCertificateDNSNamesToMatch(cr, key); err != nil {
		return nil, err
	}
	if err := certificaterequests.ExpectCertificateOrganizationToMatch(cr, key); err != nil {
		return nil, err
	}
	if err := certificaterequests.ExpectCertificateIPsToMatch(cr, key); err != nil {
		return nil, err
	}
	if err := certificaterequests.ExpectCertificateURIsToMatch(cr, key); err != nil {
		return nil, err
	}

	// Verify KU and EKU
	{
		var keyAlg cmapi.PrivateKeyAlgorithm
		switch csr.PublicKeyAlgorithm {
		case x509.RSA:
			keyAlg = cmapi.RSAKeyAlgorithm
		case x509.ECDSA:
			keyAlg = cmapi.ECDSAKeyAlgorithm
		case x509.Ed25519:
			keyAlg = cmapi.Ed25519KeyAlgorithm
		default:
			return nil, fmt.Errorf("unsupported key algorithm type: %s", csr.PublicKeyAlgorithm)
		}

		expectedKeyUsages, expectedExtendedKeyUsages, err := computeExpectedKeyUsages(cr.Spec.Usages, cr.Spec.IsCA, keyAlg, issuerSpec)
		if err != nil {
			return nil, fmt.Errorf("failed to compute expected key usages: %s", err)
		}

		if !h.keyUsagesMatch(cert.KeyUsage, cert.ExtKeyUsage,
			expectedKeyUsages, expectedExtendedKeyUsages) {
			return nil, fmt.Errorf("key usages and extended key usages do not match: exp=%s got=%s exp=%s got=%s",
				apiutil.KeyUsageStrings(expectedKeyUsages), apiutil.KeyUsageStrings(cert.KeyUsage),
				apiutil.ExtKeyUsageStrings(expectedExtendedKeyUsages), apiutil.ExtKeyUsageStrings(cert.ExtKeyUsage))
		}
	}

	if err := certificaterequests.ExpectConditionApproved(cr, key); err != nil {
		return nil, err
	}
	if err := certificaterequests.ExpectConditionNotDenied(cr, key); err != nil {
		return nil, err
	}

	return cert, nil
}

func (h *Helper) WaitCertificateRequestIssuedValid(ctx context.Context, ns, name string, timeout time.Duration, key crypto.Signer) error {
	cr, err := h.WaitForCertificateRequestReady(ctx, ns, name, timeout)
	if err != nil {
		log.Logf("Error waiting for CertificateRequest to become Ready: %v", err)
		return kerrors.NewAggregate([]error{
			err,
			h.Kubectl(ns).DescribeResource(ctx, "certificaterequest", name),
			h.Kubectl(ns).Describe(ctx, "order", "challenge"),
		})
	}

	_, err = h.ValidateIssuedCertificateRequest(ctx, cr, key)
	if err != nil {
		log.Logf("Error validating issued certificate: %v", err)
		return kerrors.NewAggregate([]error{
			err,
			h.Kubectl(ns).DescribeResource(ctx, "certificaterequest", name),
			h.Kubectl(ns).Describe(ctx, "order", "challenge"),
		})
	}

	return nil
}

func (h *Helper) WaitCertificateRequestIssuedValidTLS(ctx context.Context, ns, name string, timeout time.Duration, key crypto.Signer, rootCAPEM []byte) error {
	if err := h.WaitCertificateRequestIssuedValid(ctx, ns, name, timeout, key); err != nil {
		return err
	}

	{
		cr, err := h.WaitForCertificateRequestReady(ctx, ns, name, timeout)
		if err != nil {
			return err
		}

		csr, err := pki.DecodeX509CertificateRequestBytes(cr.Spec.Request)
		if err != nil {
			return fmt.Errorf("failed to decode CertificateRequest's Spec.Request: %s", err)
		}

		cert, err := pki.DecodeX509CertificateBytes(cr.Status.Certificate)
		if err != nil {
			return err
		}

		expectedDNSNames := csr.DNSNames
		var expectedDNSName string
		if len(expectedDNSNames) > 0 {
			expectedDNSName = expectedDNSNames[0]
		}

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
			return err
		}
	}

	return nil
}

// computeExpectedKeyUsages computes the expected KUs and EKUs based on the
// requested usages (from a Certificate or CertificateRequest) and the Issuer
// spec.
// This is to account for the fact that different issuers may add, drop, or
// override the KUs and EKUs. Some completely ignore the requested usages while
// others respect some or all of the requested usages.
// There are also some special cases where the usages are influenced by the key
// algorithm and the isCA field.
func computeExpectedKeyUsages(requestedUsages []cmapi.KeyUsage, isCA bool, keyAlg cmapi.PrivateKeyAlgorithm, issuerSpec *cmapi.IssuerSpec) (x509.KeyUsage, []x509.ExtKeyUsage, error) {

	requestedKeyUsages, requestedExtendedKeyUsages, err := pki.KeyUsagesForCertificateOrCertificateRequest(requestedUsages, isCA)
	var expectedKeyUsages x509.KeyUsage
	if err != nil {
		return expectedKeyUsages, nil, fmt.Errorf("failed to build key usages from certificate: %s", err)
	}

	// By default we assume that issuers will satisfy the requested KUs and EKUs.
	expectedKeyUsages = requestedKeyUsages
	expectedExtendedKeyUsages := sets.New(requestedExtendedKeyUsages...)

	switch {
	case issuerSpec.ACME != nil:
		// The ACME test server "Pebble" only adds one EKU: "server
		// auth" and only adds one KU: "Digital Signature".
		// It ignores any other KUs in the CSR.
		//    - https://github.com/letsencrypt/pebble/pull/472
		if issuerSpec.ACME != nil {
			expectedKeyUsages = x509.KeyUsageDigitalSignature
			expectedExtendedKeyUsages.Clear().Insert(x509.ExtKeyUsageServerAuth)
		}
	case issuerSpec.Vault != nil:
		// Vault issuers will add "server auth" and "client auth" extended key
		// usages by default so we need to add them to the list of expected usages
		// Vault issuers will also add "key agreement" key usage
		expectedExtendedKeyUsages.Insert(x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
		expectedKeyUsages |= x509.KeyUsageKeyAgreement

	case issuerSpec.Venafi != nil:
		// Venafi issue adds "server auth" key usage
		expectedExtendedKeyUsages.Insert(x509.ExtKeyUsageServerAuth)
	}

	// Most issuers will drop the "key encipherment" KU, if using ECDSA keys.
	// The best explanation I can find is: https://security.stackexchange.com/a/224509
	// The exceptions are the CA and SelfSigned issuers.
	//
	// TODO(wallrj): Perhaps CA and SelfSigned issuers should also drop or
	// reject KeyEncipherment for ECDSA certificates.
	if issuerSpec.SelfSigned == nil && issuerSpec.CA == nil && keyAlg == cmapi.ECDSAKeyAlgorithm {
		expectedKeyUsages &^= x509.KeyUsageKeyEncipherment
	}

	return expectedKeyUsages, sets.List(expectedExtendedKeyUsages), nil
}
