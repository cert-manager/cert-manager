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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/e2e/framework"
	"github.com/cert-manager/cert-manager/test/e2e/framework/addon"
	"github.com/cert-manager/cert-manager/test/e2e/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/test/e2e/suite/issuers/acme/dnsproviders"
	"github.com/cert-manager/cert-manager/test/e2e/util"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

type dns01Provider interface {
	Details() *dnsproviders.Details
	addon.Addon
}

var _ = framework.CertManagerDescribe("ACME Certificate (DNS01)", func() {
	// TODO: add better logic to handle other DNS providers
	testRFC2136DNSProvider()
})

func testRFC2136DNSProvider() bool {
	name := "rfc2136"
	return Context("With "+name+" credentials configured", func() {
		f := framework.NewDefaultFramework("create-acme-certificate-dns01-" + name)

		issuerName := "test-acme-issuer"
		certificateName := "test-acme-certificate"
		certificateSecretName := "test-acme-certificate"

		p := &dnsproviders.RFC2136{}
		f.RequireAddon(p)

		dnsDomain := ""

		// ACME Issuer does not return a ca.crt. See:
		// https://github.com/cert-manager/cert-manager/issues/1571
		unsupportedFeatures := featureset.NewFeatureSet(featureset.SaveCAToSecret)
		validations := f.Helper().ValidationSetForUnsupportedFeatureSet(unsupportedFeatures)

		BeforeEach(func() {
			By("Creating an Issuer")
			dnsDomain = p.Details().NewTestDomain()
			issuer := gen.Issuer(issuerName,
				gen.SetIssuerACME(cmacme.ACMEIssuer{
					SkipTLSVerify: true,
					Server:        f.Config.Addons.ACMEServer.URL,
					Email:         testingACMEEmail,
					PrivateKey: cmmeta.SecretKeySelector{
						LocalObjectReference: cmmeta.LocalObjectReference{
							Name: testingACMEPrivateKey,
						},
					},
					Solvers: []cmacme.ACMEChallengeSolver{
						{
							DNS01: &p.Details().ProviderConfig,
						},
					},
				}))
			issuer.Namespace = f.Namespace.Name
			issuer, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), issuer, metav1.CreateOptions{})
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

		AfterEach(func() {
			By("Cleaning up")
			f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(context.TODO(), issuerName, metav1.DeleteOptions{})
			f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(context.TODO(), testingACMEPrivateKey, metav1.DeleteOptions{})
			f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(context.TODO(), certificateSecretName, metav1.DeleteOptions{})
		})

		It("should obtain a signed certificate for a regular domain", func() {
			By("Creating a Certificate")

			certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

			cert := gen.Certificate(certificateName,
				gen.SetCertificateSecretName(certificateSecretName),
				gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName}),
				gen.SetCertificateDNSNames(dnsDomain),
			)
			cert.Namespace = f.Namespace.Name

			cert, err := certClient.Create(context.TODO(), cert, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, certificateName, time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName, validations...)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should obtain a signed certificate for a wildcard domain", func() {
			By("Creating a Certificate")

			cert := gen.Certificate(certificateName,
				gen.SetCertificateSecretName(certificateSecretName),
				gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName}),
				gen.SetCertificateDNSNames("*."+dnsDomain),
			)
			cert.Namespace = f.Namespace.Name

			cert, err := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Create(context.TODO(), cert, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, certificateName, time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName, validations...)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should obtain a signed certificate for a wildcard and apex domain", func() {
			By("Creating a Certificate")

			cert := gen.Certificate(certificateName,
				gen.SetCertificateSecretName(certificateSecretName),
				gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName}),
				gen.SetCertificateDNSNames("*."+dnsDomain, dnsDomain),
			)
			cert.Namespace = f.Namespace.Name

			cert, err := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Create(context.TODO(), cert, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			// use a longer timeout for this, as it requires performing 2 dns validations in serial
			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, certificateName, time.Minute*10)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName, validations...)
			Expect(err).NotTo(HaveOccurred())
		})
	})
}
