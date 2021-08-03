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
	"os"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	v1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"github.com/jetstack/cert-manager/test/e2e/framework/log"
)

func (h *Helper) waitPollImmediateCertificate(client clientset.CertificateInterface, name string, check func(*v1.Certificate) bool, interval time.Duration, timeout time.Duration) (*cmapi.Certificate, error) {
	var certificate *v1.Certificate = nil
	pollErr := wait.PollImmediate(interval, timeout, func() (bool, error) {
		var err error
		certificate, err = client.Get(context.TODO(), name, metav1.GetOptions{})
		if nil != err {
			certificate = nil
			return false, fmt.Errorf("error getting Certificate %v: %v", name, err)
		}

		return check(certificate), nil
	})

	if pollErr != nil && certificate != nil {
		fmt.Fprintf(os.Stderr, "Failed waiting for certificate %v: %v\n", name, pollErr.Error())

		if len(certificate.Status.Conditions) > 0 {
			fmt.Fprintf(os.Stderr, "Perceived certificate conditions:\n")
			for _, cond := range certificate.Status.Conditions {
				fmt.Fprintf(os.Stderr, "- Last Status: '%s' Reason: '%s', Message: '%s'\n", cond.Status, cond.Reason, cond.Message)
			}
		}

		fmt.Fprintf(os.Stderr, "Certificate description:\n")
		h.Kubectl(certificate.Namespace).DescribeResource("certificate", name)
		fmt.Fprintf(os.Stderr, "Order and challenge descriptions:\n")
		h.Kubectl(certificate.Namespace).Describe("order", "challenge")

		fmt.Fprintf(os.Stderr, "Certificaterequest description:\n")
		crName, err := apiutil.ComputeName(certificate.Name, certificate.Spec)
		if err != nil {
			log.Logf("Failed to compute CertificateRequest name from certificate: %s", err)
		} else {
			h.Kubectl(certificate.Namespace).DescribeResource("certificaterequest", crName)
		}
	}
	return certificate, pollErr
}

// WaitForCertificateReady waits for the certificate resource to enter a Ready state and to leave the Issuing state.
func (h *Helper) WaitForCertificateReady(ns, name string, timeout time.Duration) (*cmapi.Certificate, error) {
	ready_true_condition := cmapi.CertificateCondition{
		Type:   cmapi.CertificateConditionReady,
		Status: cmmeta.ConditionTrue,
	}
	issuing_condition := cmapi.CertificateCondition{
		Type: cmapi.CertificateConditionIssuing,
	}

	return h.waitPollImmediateCertificate(h.CMClient.CertmanagerV1().Certificates(ns), name, func(certificate *v1.Certificate) bool {
		if !apiutil.CertificateHasCondition(certificate, ready_true_condition) {
			log.Logf("Expected Certificate %v condition %v=%v but it has: %v", certificate.Name, ready_true_condition.Type, ready_true_condition.Status, certificate.Status.Conditions)
			return false
		}

		if apiutil.CertificateHasCondition(certificate, issuing_condition) {
			log.Logf("Expected Certificate %v condition %v to be missing but it has: %v", certificate.Name, issuing_condition.Type, certificate.Status.Conditions)
			return false
		}

		return true
	}, 500*time.Millisecond, timeout)
}

// WaitForCertificateReadyUpdate waits for the certificate resource to enter a
// Ready state and to leave the Issuing state. If the provided cert was in a
// Ready state already, the function waits for a state transition to have happened.
func (h *Helper) WaitForCertificateReadyUpdate(cert *cmapi.Certificate, timeout time.Duration) (*cmapi.Certificate, error) {
	ready_true_condition := cmapi.CertificateCondition{
		Type:               cmapi.CertificateConditionReady,
		Status:             cmmeta.ConditionTrue,
		ObservedGeneration: cert.Generation,
	}
	issuing_condition := cmapi.CertificateCondition{
		Type: cmapi.CertificateConditionIssuing,
	}
	return h.waitPollImmediateCertificate(h.CMClient.CertmanagerV1().Certificates(cert.Namespace), cert.Name, func(certificate *v1.Certificate) bool {
		if !apiutil.CertificateHasConditionWithObservedGeneration(certificate, ready_true_condition) {
			log.Logf(
				"Expected Certificate %v condition %v=%v (generation >= %v) but it has: %v",
				certificate.Name,
				ready_true_condition.Type,
				ready_true_condition.Status,
				ready_true_condition.ObservedGeneration,
				certificate.Status.Conditions,
			)
			return false
		}

		if apiutil.CertificateHasCondition(certificate, issuing_condition) {
			log.Logf("Expected Certificate %v condition %v to be missing but it has: %v", certificate.Name, issuing_condition.Type, certificate.Status.Conditions)
			return false
		}

		return true
	}, 500*time.Millisecond, timeout)
}

// WaitForCertificateReadyUpdate waits for the certificate resource to enter a
// Ready=False state and to leave the Issuing state. If the provided cert was
// in a Ready=False state already, the function waits for a state transition to have happened.
func (h *Helper) WaitForCertificateNotReadyUpdate(cert *cmapi.Certificate, timeout time.Duration) (*cmapi.Certificate, error) {
	ready_false_condition := cmapi.CertificateCondition{
		Type:               cmapi.CertificateConditionReady,
		Status:             cmmeta.ConditionFalse,
		ObservedGeneration: cert.Generation,
	}
	issuing_condition := cmapi.CertificateCondition{
		Type: cmapi.CertificateConditionIssuing,
	}
	return h.waitPollImmediateCertificate(h.CMClient.CertmanagerV1().Certificates(cert.Namespace), cert.Name, func(certificate *v1.Certificate) bool {
		if !apiutil.CertificateHasCondition(certificate, ready_false_condition) {
			log.Logf(
				"Expected Certificate %v condition %v=%v (generation >= %v) but it has: %v",
				certificate.Name,
				ready_false_condition.Type,
				ready_false_condition.Status,
				ready_false_condition.ObservedGeneration,
				certificate.Status.Conditions,
			)
			return false
		}

		if apiutil.CertificateHasCondition(certificate, issuing_condition) {
			log.Logf("Expected Certificate %v condition %v to be missing but it has: %v", certificate.Name, issuing_condition.Type, certificate.Status.Conditions)
			return false
		}

		return true
	}, 500*time.Millisecond, timeout)
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
