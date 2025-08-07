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

// E2E tests for the ACME profiles extension

package certificate

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/validation/certificaterequests"
	e2eutil "github.com/cert-manager/cert-manager/e2e-tests/util"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.CertManagerDescribe("ACME Profiles Extension", func() {
	f := framework.NewDefaultFramework("acme-profiles-extension")
	h := f.Helper()

	var acmeProfile string
	var acmeIngressDomain string
	issuerName := "test-acme-issuer"
	certificateRequestName := "test-acme-certificate-request"
	// fixedIngressName is the name of an ingress resource that is configured
	// with a challenge solve.
	// To utilise this solver, add the 'testing.cert-manager.io/fixed-ingress: "true"' label.
	fixedIngressName := "testingress"

	// JustBeforeEach is necessary here so that the `acmeProfile` variable can
	// be mutated before we create the Issuer resource.
	// https://onsi.github.io/ginkgo/#separating-creation-and-configuration-justbeforeeach
	JustBeforeEach(func(testingCtx context.Context) {
		acmeIngressDomain = e2eutil.RandomSubdomain(f.Config.Addons.IngressController.Domain)

		solvers := []cmacme.ACMEChallengeSolver{
			{
				HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
					Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
						Class: &f.Config.Addons.IngressController.IngressClass,
					},
				},
			},
			{
				Selector: &cmacme.CertificateDNSNameSelector{
					MatchLabels: map[string]string{
						"testing.cert-manager.io/fixed-ingress": "true",
					},
				},
				HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
					Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{
						Name: fixedIngressName,
					},
				},
			},
		}
		acmeIssuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerACMEEmail(testingACMEEmail),
			gen.SetIssuerACMEURL(f.Config.Addons.ACMEServer.URL),
			gen.SetIssuerACMEPrivKeyRef(testingACMEPrivateKey),
			gen.SetIssuerACMESkipTLSVerify(true),
			gen.SetIssuerACMESolvers(solvers),
			gen.SetIssuerACMEProfile(acmeProfile),
		)
		By(fmt.Sprintf("Creating an Issuer with profile: %q", acmeProfile))
		_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(testingCtx, acmeIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(testingCtx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func(testingCtx context.Context) {
		By("Cleaning up")
		err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(testingCtx, issuerName, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
		err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(testingCtx, testingACMEPrivateKey, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	When("the Issuer has a profile which is supported by the ACME server", func() {
		BeforeEach(func(testingCtx context.Context) {
			// The supported profiles are defined in the Pebble configuration:
			// <repository>/make/config/pebble/charts/templates/configmap.yaml
			acmeProfile = "123h"
		})

		It("should obtain a signed certificate, with duration matching the profile", func(testingCtx context.Context) {
			crClient := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name)

			By("Creating a CertificateRequest")
			csr, key, err := gen.CSR(x509.RSA, gen.SetCSRDNSNames(acmeIngressDomain))
			Expect(err).NotTo(HaveOccurred())
			cr := gen.CertificateRequest(certificateRequestName,
				gen.SetCertificateRequestNamespace(f.Namespace.Name),
				gen.SetCertificateRequestIssuer(cmmeta.IssuerReference{Kind: v1.IssuerKind, Name: issuerName}),
				gen.SetCertificateRequestCSR(csr),
			)

			_, err = crClient.Create(testingCtx, cr, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the Certificate is Ready")
			_, err = h.WaitForCertificateRequestReady(testingCtx, f.Namespace.Name, certificateRequestName, time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the Certificate duration matches the profile")
			err = h.ValidateCertificateRequest(
				types.NamespacedName{Namespace: cr.Namespace, Name: cr.Name},
				key,
				certificaterequests.ExpectDuration(time.Hour*123, time.Second),
			)
			Expect(err).NotTo(HaveOccurred())
		})
	})
	When("the Issuer has a profile which is not supported by the ACME server", func() {
		BeforeEach(func(testingCtx context.Context) {
			acmeProfile = "unsupported-profile"
		})

		It("should set the CertificateRequest as failed, with an actionable error message", func(testingCtx context.Context) {
			crClient := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name)

			By("Creating a CertificateRequest")
			csr, _, err := gen.CSR(x509.RSA, gen.SetCSRDNSNames(acmeIngressDomain))
			Expect(err).NotTo(HaveOccurred())
			cr := gen.CertificateRequest(certificateRequestName,
				gen.SetCertificateRequestNamespace(f.Namespace.Name),
				gen.SetCertificateRequestIssuer(cmmeta.IssuerReference{Kind: v1.IssuerKind, Name: issuerName}),
				gen.SetCertificateRequestCSR(csr),
			)

			_, err = crClient.Create(testingCtx, cr, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the Certificate is failed")
			cr, err = h.WaitForCertificateRequestReady(testingCtx, f.Namespace.Name, certificateRequestName, time.Minute*5)
			Expect(err).To(MatchError(helper.ErrCertificateRequestFailed))
			readyCondition := apiutil.GetCertificateRequestCondition(cr, v1.CertificateRequestConditionReady)
			Expect(readyCondition.Message).To(ContainSubstring(
				"Failed to create Order: acme: certificate authority does not advertise a profile with name unsupported-profile",
			))
		})
	})
})
