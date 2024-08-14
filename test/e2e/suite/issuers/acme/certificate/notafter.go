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

package certificate

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/validation"
	"github.com/cert-manager/cert-manager/e2e-tests/util"
	e2eutil "github.com/cert-manager/cert-manager/e2e-tests/util"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.CertManagerDescribe("ACME Certificate (HTTP01 + Not After)", func() {
	f := framework.NewDefaultFramework("create-acme-certificate-duration")
	ctx := context.TODO()

	var acmeIngressDomain string
	issuerName := "test-acme-issuer"
	certificateName := "test-acme-certificate"
	certificateSecretName := "test-acme-certificate"
	// fixedIngressName is the name of an ingress resource that is configured
	// with a challenge solve.
	// To utilise this solver, add the 'testing.cert-manager.io/fixed-ingress: "true"' label.
	fixedIngressName := "testingress"

	// ACME Issuer does not return a ca.crt. See:
	// https://github.com/cert-manager/cert-manager/issues/1571
	unsupportedFeatures := featureset.NewFeatureSet(featureset.SaveCAToSecret)
	validations := validation.CertificateSetForUnsupportedFeatureSet(unsupportedFeatures)

	BeforeEach(func() {
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
			gen.SetIssuerACMEEmail(f.Config.Addons.ACMEServer.TestingACMEEmail),
			gen.SetIssuerACMEURL(f.Config.Addons.ACMEServer.URL),
			gen.SetIssuerACMEPrivKeyRef(f.Config.Addons.ACMEServer.TestingACMEPrivateKey),
			gen.SetIssuerACMESkipTLSVerify(true),
			// Enable Duration feature to set NotAfter
			gen.SetIssuerACMEDuration(true),
			gen.SetIssuerACMESolvers(solvers))
		By("Creating an Issuer")
		_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, acmeIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
		By("Verifying the ACME account URI is set")
		err = util.WaitForIssuerStatusFunc(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			func(i *v1.Issuer) (bool, error) {
				if i.GetStatus().ACMEStatus().URI == "" {
					return false, nil
				}
				return true, nil
			})
		Expect(err).NotTo(HaveOccurred())
		By("Verifying ACME account private key exists")
		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(ctx, f.Config.Addons.ACMEServer.TestingACMEPrivateKey, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		if len(secret.Data) != 1 {
			Fail("Expected 1 key in ACME account private key secret, but there was %d", len(secret.Data))
		}
	})

	JustBeforeEach(func() {
		acmeIngressDomain = e2eutil.RandomSubdomain(f.Config.Addons.IngressController.Domain)
	})

	AfterEach(func() {
		By("Cleaning up")
		err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(ctx, issuerName, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
		err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(ctx, f.Config.Addons.ACMEServer.TestingACMEPrivateKey, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should obtain a signed certificate with a single CN from the ACME server with 1 hour validity", func() {
		certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

		By("Creating a Certificate")
		cert := gen.Certificate(certificateName,
			gen.SetCertificateDuration(&metav1.Duration{Duration: time.Hour}),
			gen.SetCertificateRenewBefore(&metav1.Duration{Duration: 45 * time.Minute}),
			gen.SetCertificateSecretName(certificateSecretName),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName}),
			gen.SetCertificateDNSNames(acmeIngressDomain),
		)
		cert.Namespace = f.Namespace.Name

		cert, err := certClient.Create(ctx, cert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be issued...")
		cert, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, cert, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Validating the issued Certificate...")
		err = f.Helper().ValidateCertificate(cert, validations...)
		Expect(err).NotTo(HaveOccurred())

		sec, err := f.Helper().WaitForSecretCertificateData(ctx, f.Namespace.Name, certificateSecretName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred(), "failed to wait for secret")

		crtPEM := sec.Data[corev1.TLSCertKey]
		crt, err := pki.DecodeX509CertificateBytes(crtPEM)
		Expect(err).NotTo(HaveOccurred(), "failed to get decode signed certificate data")

		// checking loosely to not hit too many timing issues as the date is defined in the controller
		// pebble issues a 5 year cert by default
		if crt.NotAfter.After(time.Now().Add(time.Hour)) {
			Fail(fmt.Sprintf("Certificate has a NotAfter time after more than 1 hour (requested duration), got %s, current time %s", crt.NotAfter.String(), time.Now().String()))
		}
	})
})
