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

	errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cert-manager/cert-manager/e2e-tests/framework/log"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapiv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	clientset "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
)

// WaitForCertificateToExist waits for the named certificate to exist and returns the certificate
func (h *Helper) WaitForCertificateToExist(ctx context.Context, namespace string, name string, timeout time.Duration) (*cmapiv1.Certificate, error) {
	client := h.CMClient.CertmanagerV1().Certificates(namespace)
	var certificate *cmapiv1.Certificate
	logf, done := log.LogBackoff()
	defer done()

	pollErr := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, timeout, true, func(ctx context.Context) (bool, error) {
		logf("Waiting for Certificate %v to exist", name)
		var err error
		certificate, err = client.Get(ctx, name, metav1.GetOptions{})
		if errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("error getting Certificate %v: %v", name, err)
		}

		return true, nil
	})
	return certificate, pollErr
}

func (h *Helper) waitForCertificateCondition(ctx context.Context, client clientset.CertificateInterface, name string, check func(*cmapiv1.Certificate) bool, timeout time.Duration) (*cmapiv1.Certificate, error) {
	var certificate *cmapiv1.Certificate
	pollErr := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, timeout, true, func(ctx context.Context) (bool, error) {
		var err error
		certificate, err = client.Get(ctx, name, metav1.GetOptions{})
		if nil != err {
			certificate = nil
			return false, fmt.Errorf("error getting Certificate %v: %v", name, err)
		}

		return check(certificate), nil
	})

	if pollErr != nil && certificate != nil {
		log.Logf("Failed waiting for certificate %v: %v\n", name, pollErr.Error())

		errs := []error{pollErr}

		log.Logf("Certificate:\n")
		errs = append(errs, h.describeCMObject(certificate))

		log.Logf("Order and challenge descriptions:\n")
		errs = append(errs, h.Kubectl(certificate.Namespace).Describe(ctx, "order", "challenge"))

		log.Logf("CertificateRequest description:\n")
		crName, err := apiutil.ComputeName(certificate.Name, certificate.Spec)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to compute CertificateRequest name from certificate: %w", err))
		} else {
			errs = append(errs, h.Kubectl(certificate.Namespace).DescribeResource(ctx, "certificaterequest", crName))
		}

		pollErr = kerrors.NewAggregate(errs)
	}
	return certificate, pollErr
}

// WaitForCertificateReadyAndDoneIssuing waits for the certificate resource to be in a Ready=True state and not be in an Issuing state.
// The Ready=True condition will be checked against the provided certificate to make sure that it is up-to-date (condition gen. >= cert gen.).
func (h *Helper) WaitForCertificateReadyAndDoneIssuing(ctx context.Context, cert *cmapiv1.Certificate, timeout time.Duration) (*cmapiv1.Certificate, error) {
	ready_true_condition := cmapiv1.CertificateCondition{
		Type:               cmapiv1.CertificateConditionReady,
		Status:             cmmeta.ConditionTrue,
		ObservedGeneration: cert.Generation,
	}
	issuing_true_condition := cmapiv1.CertificateCondition{
		Type:   cmapiv1.CertificateConditionIssuing,
		Status: cmmeta.ConditionTrue,
	}
	logf, done := log.LogBackoff()
	defer done()
	return h.waitForCertificateCondition(ctx, h.CMClient.CertmanagerV1().Certificates(cert.Namespace), cert.Name, func(certificate *cmapiv1.Certificate) bool {
		if !apiutil.CertificateHasConditionWithObservedGeneration(certificate, ready_true_condition) {
			logf(
				"Expected Certificate %v condition %v=%v (generation >= %v) but it has: %v",
				certificate.Name,
				ready_true_condition.Type,
				ready_true_condition.Status,
				ready_true_condition.ObservedGeneration,
				certificate.Status.Conditions,
			)
			return false
		}

		if apiutil.CertificateHasCondition(certificate, issuing_true_condition) {
			logf("Expected Certificate %v condition %v to be missing but it has: %v", certificate.Name, issuing_true_condition.Type, certificate.Status.Conditions)
			return false
		}

		if certificate.Status.NextPrivateKeySecretName != nil {
			logf("Expected Certificate %v 'next-private-key-secret-name' attribute to be empty but has: %v", certificate.Name, *certificate.Status.NextPrivateKeySecretName)
			return false
		}

		return true
	}, timeout)
}

// WaitForCertificateNotReadyAndDoneIssuing waits for the certificate resource to be in a Ready=False state and not be in an Issuing state.
// The Ready=False condition will be checked against the provided certificate to make sure that it is up-to-date (condition gen. >= cert gen.).
func (h *Helper) WaitForCertificateNotReadyAndDoneIssuing(ctx context.Context, cert *cmapiv1.Certificate, timeout time.Duration) (*cmapiv1.Certificate, error) {
	ready_false_condition := cmapiv1.CertificateCondition{
		Type:               cmapiv1.CertificateConditionReady,
		Status:             cmmeta.ConditionFalse,
		ObservedGeneration: cert.Generation,
	}
	issuing_true_condition := cmapiv1.CertificateCondition{
		Type:   cmapiv1.CertificateConditionIssuing,
		Status: cmmeta.ConditionTrue,
	}
	logf, done := log.LogBackoff()
	defer done()
	return h.waitForCertificateCondition(ctx, h.CMClient.CertmanagerV1().Certificates(cert.Namespace), cert.Name, func(certificate *cmapiv1.Certificate) bool {
		if !apiutil.CertificateHasConditionWithObservedGeneration(certificate, ready_false_condition) {
			logf(
				"Expected Certificate %v condition %v=%v (generation >= %v) but it has: %v",
				certificate.Name,
				ready_false_condition.Type,
				ready_false_condition.Status,
				ready_false_condition.ObservedGeneration,
				certificate.Status.Conditions,
			)
			return false
		}

		if apiutil.CertificateHasCondition(certificate, issuing_true_condition) {
			logf("Expected Certificate %v condition %v to be missing but it has: %v", certificate.Name, issuing_true_condition.Type, certificate.Status.Conditions)
			return false
		}

		if certificate.Status.NextPrivateKeySecretName != nil {
			logf("Expected Certificate %v 'next-private-key-secret-name' attribute to be empty but has: %v", certificate.Name, *certificate.Status.NextPrivateKeySecretName)
			return false
		}

		return true
	}, timeout)
}

func (h *Helper) waitForIssuerCondition(ctx context.Context, client clientset.IssuerInterface, name string, check func(issuer *cmapiv1.Issuer) bool, timeout time.Duration) (*cmapiv1.Issuer, error) {
	var issuer *cmapiv1.Issuer
	pollErr := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, timeout, true, func(ctx context.Context) (bool, error) {
		var err error
		issuer, err = client.Get(ctx, name, metav1.GetOptions{})
		if nil != err {
			issuer = nil
			return false, fmt.Errorf("error getting Issuer %v: %v", name, err)
		}
		return check(issuer), nil
	})

	if pollErr != nil && issuer != nil {
		log.Logf("Failed waiting for issuer %v :%v\n", name, pollErr.Error())

		log.Logf("Issuer:\n")
		pollErr = kerrors.NewAggregate([]error{pollErr, h.describeCMObject(issuer)})
	}

	return issuer, pollErr
}

// WaitIssuerReady waits for the Issuer resource to be in a Ready=True state
// The Ready=True condition will be checked against the provided issuer to make sure it's ready.
func (h *Helper) WaitIssuerReady(ctx context.Context, issuer *cmapiv1.Issuer, timeout time.Duration) (*cmapiv1.Issuer, error) {
	ready_true_condition := cmapiv1.IssuerCondition{
		Type:   cmapiv1.IssuerConditionReady,
		Status: cmmeta.ConditionTrue,
	}

	logf, done := log.LogBackoff()
	defer done()
	return h.waitForIssuerCondition(ctx, h.CMClient.CertmanagerV1().Issuers(issuer.Namespace), issuer.Name, func(issuer *cmapiv1.Issuer) bool {
		if !apiutil.IssuerHasCondition(issuer, ready_true_condition) {
			logf(
				"Expected Issuer %v condition %v=%v but it has: %v",
				issuer.Name,
				ready_true_condition.Type,
				ready_true_condition.Status,
				issuer.Status.Conditions,
			)
			return false
		}
		return true
	}, timeout)
}

func (h *Helper) waitForClusterIssuerCondition(ctx context.Context, client clientset.ClusterIssuerInterface, name string, check func(issuer *cmapiv1.ClusterIssuer) bool, timeout time.Duration) (*cmapiv1.ClusterIssuer, error) {
	var issuer *cmapiv1.ClusterIssuer
	pollErr := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, timeout, true, func(ctx context.Context) (bool, error) {
		var err error
		issuer, err = client.Get(ctx, name, metav1.GetOptions{})
		if nil != err {
			issuer = nil
			return false, fmt.Errorf("error getting Issuer %v: %v", name, err)
		}
		return check(issuer), nil
	})

	if pollErr != nil && issuer != nil {
		log.Logf("Failed waiting for issuer %v :%v\n", name, pollErr.Error())

		log.Logf("Issuer:\n")
		pollErr = kerrors.NewAggregate([]error{pollErr, h.describeCMObject(issuer)})
	}

	return issuer, pollErr
}

// WaitClusterIssuerReady waits for the Cluster Issuer resource to be in a Ready=True state
// The Ready=True condition will be checked against the provided issuer to make sure it's ready.
func (h *Helper) WaitClusterIssuerReady(ctx context.Context, issuer *cmapiv1.ClusterIssuer, timeout time.Duration) (*cmapiv1.ClusterIssuer, error) {
	ready_true_condition := cmapiv1.IssuerCondition{
		Type:   cmapiv1.IssuerConditionReady,
		Status: cmmeta.ConditionTrue,
	}
	logf, done := log.LogBackoff()
	defer done()
	return h.waitForClusterIssuerCondition(ctx, h.CMClient.CertmanagerV1().ClusterIssuers(), issuer.Name, func(issuer *cmapiv1.ClusterIssuer) bool {
		if !apiutil.IssuerHasCondition(issuer, ready_true_condition) {
			logf(
				"Expected Cluster Issuer %v condition %v=%v but it has: %v",
				issuer.Name,
				ready_true_condition.Type,
				ready_true_condition.Status,
				issuer.Status.Conditions,
			)
			return false
		}
		return true
	}, timeout)
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
