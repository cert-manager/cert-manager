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

package selfsigned

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/e2e/framework"
	"github.com/cert-manager/cert-manager/test/e2e/util"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var _ = framework.CertManagerDescribe("SelfSigned CertificateRequest", func() {
	f := framework.NewDefaultFramework("create-selfsigned-certificaterequest")
	h := f.Helper()

	var basicCR *v1.CertificateRequest
	issuerName := "test-selfsigned-issuer"
	certificateRequestName := "test-selfsigned-certificaterequest"
	certificateRequestSecretName := "test-selfsigned-private-key"

	JustBeforeEach(func() {
		By("Creating an Issuer")
		_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), util.NewCertManagerSelfSignedIssuer(issuerName), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())

		By("Building CertificateRequest")
		basicCR = gen.CertificateRequest(certificateRequestName,
			gen.SetCertificateRequestNamespace(f.Namespace.Name),
			gen.SetCertificateRequestIsCA(true),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
				Name:  issuerName,
				Group: certmanager.GroupName,
				Kind:  "Issuer",
			}),
			gen.AddCertificateRequestAnnotations(map[string]string{
				v1.CertificateRequestPrivateKeyAnnotationKey: certificateRequestSecretName,
			}),
		)
	})

	AfterEach(func() {
		By("Cleaning up")
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(context.TODO(), certificateRequestSecretName, metav1.DeleteOptions{})
		f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(context.TODO(), issuerName, metav1.DeleteOptions{})
	})

	Context("Self Signed and private key", func() {

		BeforeEach(func() {
			By("Creating a signing keypair fixture")
			_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), newPrivateKeySecret(
				certificateRequestSecretName, f.Namespace.Name, rootRSAKey), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should generate a valid certificate from CSR backed by a RSA key", func() {
			crClient := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name)

			By("Creating a CertificateRequest")
			csr, err := generateRSACSR()
			Expect(err).NotTo(HaveOccurred())

			_, err = crClient.Create(context.TODO(), gen.CertificateRequestFrom(basicCR,
				gen.SetCertificateRequestCSR(csr),
			), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the Certificate is valid")
			err = h.WaitCertificateRequestIssuedValid(f.Namespace.Name, certificateRequestName, time.Second*30, rootRSAKeySigner)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should be able to obtain an ECDSA Certificate backed by a ECSDA key", func() {
			// Replace RSA key secret with ECDSA one
			_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Update(context.TODO(), newPrivateKeySecret(
				certificateRequestSecretName, f.Namespace.Name, rootECKey), metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())

			crClient := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name)
			By("Creating a CertificateRequest")
			csr, err := generateECCSR()
			Expect(err).NotTo(HaveOccurred())

			_, err = crClient.Create(context.TODO(), gen.CertificateRequestFrom(basicCR,
				gen.SetCertificateRequestCSR(csr),
			), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the Certificate is valid")
			err = h.WaitCertificateRequestIssuedValid(f.Namespace.Name, certificateRequestName, time.Second*30, rootECKeySigner)
			Expect(err).NotTo(HaveOccurred())
		})

		cases := []struct {
			inputDuration    *metav1.Duration
			expectedDuration time.Duration
			label            string
		}{
			{
				inputDuration:    &metav1.Duration{Duration: time.Hour * 24 * 35},
				expectedDuration: time.Hour * 24 * 35,
				label:            "35 days",
			},
			{
				inputDuration:    nil,
				expectedDuration: time.Hour * 24 * 90,
				label:            "the default duration (90 days)",
			},
		}
		for _, v := range cases {
			It("should generate a signed certificate valid for "+v.label, func() {
				crClient := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name)

				By("Creating a CertificateRequest")
				csr, err := generateRSACSR()
				Expect(err).NotTo(HaveOccurred())

				_, err = crClient.Create(context.TODO(), gen.CertificateRequestFrom(basicCR,
					gen.SetCertificateRequestCSR(csr),
				), metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying the CertificateRequest is valid")
				err = h.WaitCertificateRequestIssuedValid(f.Namespace.Name, certificateRequestName, time.Second*30, rootRSAKeySigner)
				Expect(err).NotTo(HaveOccurred())
				cr, err := crClient.Get(context.TODO(), certificateRequestName, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				f.CertificateRequestDurationValid(cr, v.expectedDuration, 0)
			})
		}
	})
})
