/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package ca

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = framework.CertManagerDescribe("CA Certificate", func() {
	f := framework.NewDefaultFramework("create-ca-certificate")
	h := f.Helper()

	issuerName := "test-ca-issuer"
	issuerSecretName := "ca-issuer-signing-keypair"
	certificateName := "test-ca-certificate"
	certificateSecretName := "test-ca-certificate"

	JustBeforeEach(func() {
		By("Creating an Issuer")
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(util.NewCertManagerCAIssuer(issuerName, issuerSecretName))
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			issuerName,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Cleaning up")
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(issuerSecretName, nil)
		f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(issuerName, nil)
	})

	Context("when the CA is the root", func() {
		BeforeEach(func() {
			By("Creating a signing keypair fixture")
			_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(newSigningKeypairSecret(issuerSecretName))
			Expect(err).NotTo(HaveOccurred())
		})

		It("should generate a signed keypair", func() {
			certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)

			By("Creating a Certificate")
			_, err := certClient.Create(util.NewCertManagerBasicCertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind, nil, nil))
			Expect(err).NotTo(HaveOccurred())
			By("Verifying the Certificate is valid")
			err = h.WaitCertificateIssuedValidTLS(f.Namespace.Name, certificateName, time.Second*30, []byte(rootCert))
			Expect(err).NotTo(HaveOccurred())
		})

		It("should be able to obtain an ECDSA key from a RSA backed issuer", func() {
			certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)

			crt := util.NewCertManagerBasicCertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind, nil, nil)
			crt.Spec.KeyAlgorithm = v1alpha1.ECDSAKeyAlgorithm
			crt.Spec.KeySize = 521

			By("Creating a Certificate")
			_, err := certClient.Create(crt)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the Certificate is valid")
			err = h.WaitCertificateIssuedValidTLS(f.Namespace.Name, certificateName, time.Second*30, []byte(rootCert))
			Expect(err).NotTo(HaveOccurred())
		})

		cases := []struct {
			inputDuration    *metav1.Duration
			inputRenewBefore *metav1.Duration
			expectedDuration time.Duration
			label            string
		}{
			{
				inputDuration:    &metav1.Duration{time.Hour * 24 * 35},
				inputRenewBefore: nil,
				expectedDuration: time.Hour * 24 * 35,
				label:            "35 days",
			},
			{
				inputDuration:    nil,
				inputRenewBefore: nil,
				expectedDuration: time.Hour * 24 * 90,
				label:            "the default duration (90 days)",
			},
		}
		for _, v := range cases {
			v := v
			It("should generate a signed keypair valid for "+v.label, func() {
				certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)

				By("Creating a Certificate")
				cert, err := certClient.Create(util.NewCertManagerBasicCertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind, v.inputDuration, v.inputRenewBefore))
				Expect(err).NotTo(HaveOccurred())
				By("Verifying the Certificate is valid")
				err = h.WaitCertificateIssuedValid(f.Namespace.Name, certificateName, time.Second*30)
				Expect(err).NotTo(HaveOccurred())
				f.CertificateDurationValid(cert, v.expectedDuration)
			})
		}
	})

	Context("when the CA is an issuer", func() {
		BeforeEach(func() {
			By("Creating a signing keypair fixture")
			_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(newSigningIssuer1KeypairSecret(issuerSecretName))
			Expect(err).NotTo(HaveOccurred())
		})

		It("should generate a signed keypair", func() {
			certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)

			By("Creating a Certificate")
			_, err := certClient.Create(util.NewCertManagerBasicCertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind, nil, nil))
			Expect(err).NotTo(HaveOccurred())
			By("Verifying the Certificate is valid")
			err = h.WaitCertificateIssuedValidTLS(f.Namespace.Name, certificateName, time.Second*30, []byte(rootCert))
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("when the CA is a second level issuer", func() {
		BeforeEach(func() {
			By("Creating a signing keypair fixture")
			_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(newSigningIssuer2KeypairSecret(issuerSecretName))
			Expect(err).NotTo(HaveOccurred())
		})

		It("should generate a signed keypair", func() {
			certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)

			By("Creating a Certificate")
			_, err := certClient.Create(util.NewCertManagerBasicCertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind, nil, nil))
			Expect(err).NotTo(HaveOccurred())
			By("Verifying the Certificate is valid")
			err = h.WaitCertificateIssuedValidTLS(f.Namespace.Name, certificateName, time.Second*30, []byte(rootCert))
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
