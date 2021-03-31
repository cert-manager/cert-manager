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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/framework/helper/featureset"
	frameworkutil "github.com/jetstack/cert-manager/test/e2e/framework/util"
	"github.com/jetstack/cert-manager/test/e2e/util"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

var _ = framework.CertManagerDescribe("ACME Certificate (HTTP01 + Not After)", func() {
	f := framework.NewDefaultFramework("create-acme-certificate-duration")

	var acmeIngressDomain string
	issuerName := "test-acme-issuer"
	certificateName := "test-acme-certificate"
	certificateSecretName := "test-acme-certificate"
	// fixedIngressName is the name of an ingress resource that is configured
	// with a challenge solve.
	// To utilise this solver, add the 'testing.cert-manager.io/fixed-ingress: "true"' label.
	fixedIngressName := "testingress"

	// ACME Issuer does not return a ca.crt. See:
	// https://github.com/jetstack/cert-manager/issues/1571
	unsupportedFeatures := featureset.NewFeatureSet(featureset.SaveCAToSecret)
	validations := f.Helper().ValidationSetForUnsupportedFeatureSet(unsupportedFeatures)

	BeforeEach(func() {
		acmeIssuer := util.NewCertManagerACMEIssuer(issuerName, f.Config.Addons.ACMEServer.URL, testingACMEEmail, testingACMEPrivateKey)
		// Enable Duration feature to set NotAfter
		acmeIssuer.Spec.ACME.EnableDurationFeature = true
		acmeIssuer.Spec.ACME.Solvers = []cmacme.ACMEChallengeSolver{
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
		By("Creating an Issuer")
		_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), acmeIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
		By("Verifying the ACME account URI is set")
		err = util.WaitForIssuerStatusFunc(f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			func(i *v1.Issuer) (bool, error) {
				if i.GetStatus().ACMEStatus().URI == "" {
					return false, nil
				}
				return true, nil
			})
		Expect(err).NotTo(HaveOccurred())
		By("Verifying ACME account private key exists")
		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.TODO(), testingACMEPrivateKey, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		if len(secret.Data) != 1 {
			Fail("Expected 1 key in ACME account private key secret, but there was %d", len(secret.Data))
		}
	})

	JustBeforeEach(func() {
		acmeIngressDomain = frameworkutil.RandomSubdomain(f.Config.Addons.IngressController.Domain)
	})

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(context.TODO(), issuerName, metav1.DeleteOptions{})
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(context.TODO(), testingACMEPrivateKey, metav1.DeleteOptions{})
	})

	It("should obtain a signed certificate with a single CN from the ACME server with 1 hour validity", func() {
		certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

		By("Creating a Certificate")
		cert := gen.Certificate(certificateName,
			gen.SetCertificateDuration(time.Hour),
			gen.SetCertificateRenewBefore(45*time.Minute),
			gen.SetCertificateSecretName(certificateSecretName),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName}),
			gen.SetCertificateDNSNames(acmeIngressDomain),
		)
		cert.Namespace = f.Namespace.Name

		_, err := certClient.Create(context.TODO(), cert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be issued...")
		err = f.Helper().WaitCertificateIssued(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Validating the issued Certificate...")
		err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName, validations...)
		Expect(err).NotTo(HaveOccurred())

		sec, err := f.Helper().WaitForSecretCertificateData(f.Namespace.Name, certificateSecretName, time.Minute*5)
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
