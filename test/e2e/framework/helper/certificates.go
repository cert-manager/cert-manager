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
	"crypto/x509"
	"fmt"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/e2e/framework/log"
	e2eutil "github.com/jetstack/cert-manager/test/e2e/util"
)

func (h *Helper) handleResult(ns, name string, cert *cmapi.Certificate, state string, err error) (*cmapi.Certificate, error) {
	if err != nil {
		log.Logf("Error waiting for Certificate to become %s: %v", state, err)
		h.Kubectl(ns).DescribeResource("certificate", name)
		h.Kubectl(ns).Describe("order", "challenge")
		h.describeCertificateRequestFromCertificate(ns, cert)
	}
	return cert, err
}

// waitForCertificateNotIssuing waits for the certificate resource to leave the Issuing state.
func (h *Helper) waitForCertificateNotIssuing(ns, name string, timeout time.Duration) (*cmapi.Certificate, error) {
	result, err := e2eutil.WaitForMissingCertificateCondition(h.CMClient.CertmanagerV1().Certificates(ns), name, cmapi.CertificateCondition{
		Type:   cmapi.CertificateConditionIssuing,
		Status: cmmeta.ConditionTrue,
	}, timeout)
	return h.handleResult(ns, name, result, "Not Issuing", err)
}

// WaitForCertificateReady waits for the certificate resource to enter a Ready state and to leave the Issuing state.
func (h *Helper) WaitForCertificateReady(ns, name string, timeout time.Duration) (*cmapi.Certificate, error) {
	result, err := e2eutil.WaitForCertificateCondition(h.CMClient.CertmanagerV1().Certificates(ns), name, cmapi.CertificateCondition{
		Type:   cmapi.CertificateConditionReady,
		Status: cmmeta.ConditionTrue,
	}, timeout)
	if err != nil {
		return h.handleResult(ns, name, result, "Ready", err)
	}
	// Making sure that the Certificate is stable (see #4239) by also waiting for the Issuing state to disappear.
	// A certificate that has state Ready=True and Issuing not set, is stable and will not change without outside changes.
	return h.waitForCertificateNotIssuing(ns, name, timeout)
}

// WaitForCertificateReadyUpdate waits for the certificate resource to enter a
// Ready state and to leave the Issuing state. If the provided cert was in a
// Ready state already, the function waits for a state transition to have happened.
func (h *Helper) WaitForCertificateReadyUpdate(cert *cmapi.Certificate, timeout time.Duration) (*cmapi.Certificate, error) {
	result, err := e2eutil.WaitForCertificateConditionWithObservedGeneration(h.CMClient.CertmanagerV1().Certificates(cert.Namespace), cert.Name, cmapi.CertificateCondition{
		Type:               cmapi.CertificateConditionReady,
		Status:             cmmeta.ConditionTrue,
		ObservedGeneration: cert.Generation,
	}, timeout)
	if err != nil {
		return h.handleResult(cert.Namespace, cert.Name, result, "Ready", err)
	}
	// Making sure that the Certificate is stable (see #4239) by also waiting for the Issuing state to disappear.
	// A certificate that has state Ready=True and Issuing not set, is stable and will not change without outside changes.
	return h.waitForCertificateNotIssuing(cert.Namespace, cert.Name, timeout)
}

// WaitForCertificateReadyUpdate waits for the certificate resource to enter a
// Ready=False state and to leave the Issuing state. If the provided cert was
// in a Ready=False state already, the function waits for a state transition to have happened.
func (h *Helper) WaitForCertificateNotReadyUpdate(cert *cmapi.Certificate, timeout time.Duration) (*cmapi.Certificate, error) {
	result, err := e2eutil.WaitForCertificateConditionWithObservedGeneration(h.CMClient.CertmanagerV1().Certificates(cert.Namespace), cert.Name, cmapi.CertificateCondition{
		Type:               cmapi.CertificateConditionReady,
		Status:             cmmeta.ConditionFalse,
		ObservedGeneration: cert.Generation,
	}, timeout)
	if err != nil {
		return h.handleResult(cert.Namespace, cert.Name, result, "Not Ready", err)
	}
	// Making sure that the Certificate is stable (see #4239) by also waiting for the Issuing state to disappear.
	// A certificate that has state Ready=False and Issuing not set, is stable and will not change without outside changes.
	return h.waitForCertificateNotIssuing(cert.Namespace, cert.Name, timeout)
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
