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

package ca

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/e2e/framework"
	"github.com/cert-manager/cert-manager/test/e2e/util"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = framework.CertManagerDescribe("CA Certificate", func() {
	f := framework.NewDefaultFramework("create-ca-certificate")

	issuerName := "test-ca-issuer"
	issuerSecretName := "ca-issuer-signing-keypair"
	certificateName := "test-ca-certificate"
	certificateSecretName := "test-ca-certificate"

	JustBeforeEach(func() {
		By("Creating an Issuer")
		_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), util.NewCertManagerCAIssuer(issuerName, issuerSecretName), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Cleaning up")
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(context.TODO(), issuerSecretName, metav1.DeleteOptions{})
		f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(context.TODO(), issuerName, metav1.DeleteOptions{})
	})

	Context("when the CA is the root", func() {
		BeforeEach(func() {
			By("Creating a signing keypair fixture")
			_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), newSigningKeypairSecret(issuerSecretName), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should generate a signed keypair", func() {
			certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

			By("Creating a Certificate")
			_, err := certClient.Create(context.TODO(), util.NewCertManagerBasicCertificate(certificateName, certificateSecretName, issuerName, v1.IssuerKind, nil, nil), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			By("Verifying the Certificate is valid")
			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, certificateName, time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should be able to obtain an ECDSA key from a RSA backed issuer", func() {
			certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

			crt := util.NewCertManagerBasicCertificate(certificateName, certificateSecretName, issuerName, v1.IssuerKind, nil, nil)
			crt.Spec.PrivateKey.Algorithm = v1.ECDSAKeyAlgorithm
			crt.Spec.PrivateKey.Size = 521

			By("Creating a Certificate")
			_, err := certClient.Create(context.TODO(), crt, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, certificateName, time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName)
			Expect(err).NotTo(HaveOccurred())
		})

		cases := []struct {
			inputDuration    *metav1.Duration
			inputRenewBefore *metav1.Duration
			expectedDuration time.Duration
			label            string
		}{
			{
				inputDuration:    &metav1.Duration{Duration: time.Hour * 24 * 35},
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
				certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

				By("Creating a Certificate")
				cert, err := certClient.Create(context.TODO(), util.NewCertManagerBasicCertificate(certificateName, certificateSecretName, issuerName, v1.IssuerKind, v.inputDuration, v.inputRenewBefore), metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				By("Waiting for the Certificate to be issued...")
				err = f.Helper().WaitCertificateIssued(f.Namespace.Name, certificateName, time.Minute*5)
				Expect(err).NotTo(HaveOccurred())

				By("Validating the issued Certificate...")
				err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName)
				Expect(err).NotTo(HaveOccurred())

				f.CertificateDurationValid(cert, v.expectedDuration, 0)
			})
		}
	})

	Context("when the CA is an issuer", func() {
		BeforeEach(func() {
			By("Creating a signing keypair fixture")
			_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), newSigningIssuer1KeypairSecret(issuerSecretName), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should generate a signed keypair", func() {
			certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

			By("Creating a Certificate")
			_, err := certClient.Create(context.TODO(), util.NewCertManagerBasicCertificate(certificateName, certificateSecretName, issuerName, v1.IssuerKind, nil, nil), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, certificateName, time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("when the CA is a second level issuer", func() {
		BeforeEach(func() {
			By("Creating a signing keypair fixture")
			_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), newSigningIssuer2KeypairSecret(issuerSecretName), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should generate a signed keypair", func() {
			certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

			By("Creating a Certificate with Usages")
			_, err := certClient.Create(context.TODO(), gen.Certificate(certificateName, gen.SetCertificateNamespace(f.Namespace.Name), gen.SetCertificateCommonName("test.domain.com"), gen.SetCertificateSecretName(certificateSecretName), gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName, Kind: v1.IssuerKind}), gen.SetCertificateKeyUsages(v1.UsageServerAuth, v1.UsageClientAuth)), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			By("Waiting for the Certificate to be issued...")
			err = f.Helper().WaitCertificateIssued(f.Namespace.Name, certificateName, time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
