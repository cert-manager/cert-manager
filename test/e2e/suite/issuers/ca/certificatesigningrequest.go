/*
Copyright 2021 The cert-manager Authors.

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
	"crypto/x509"
	"net"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	experimentalapi "github.com/jetstack/cert-manager/pkg/apis/experimental/v1alpha1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/util"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

var _ = framework.CertManagerDescribe("CA CertificateSigningRequest", func() {
	f := framework.NewDefaultFramework("create-ca-certificate-kube-csr")
	h := f.Helper()

	var (
		issuerName       = "test-ca-issuer"
		issuerSecretName = "ca-issuer-signing-keypair"

		exampleDNSNames    = []string{"dnsName1.co", "dnsName2.ninja"}
		exampleIPAddresses = []net.IP{
			[]byte{8, 8, 8, 8},
			[]byte{1, 1, 1, 1},
		}

		kubeCSRName string
	)

	JustBeforeEach(func() {
		By("Creating an Issuer")
		issuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerCASecretName(issuerSecretName))
		_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), issuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			cmapi.IssuerCondition{
				Type:   cmapi.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Cleaning up")
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(context.TODO(), issuerSecretName, metav1.DeleteOptions{})
		f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(context.TODO(), issuerName, metav1.DeleteOptions{})
		if len(kubeCSRName) > 0 {
			f.KubeClientSet.CertificatesV1().CertificateSigningRequests().Delete(context.TODO(), kubeCSRName, metav1.DeleteOptions{})
			kubeCSRName = ""
		}
	})

	Context("when the CA is the root", func() {
		BeforeEach(func() {
			By("Creating a signing keypair fixture")
			_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), newSigningKeypairSecret(issuerSecretName), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should generate a valid certificate from CertificateSigningRequest", func() {
			csrClient := f.KubeClientSet.CertificatesV1().CertificateSigningRequests()

			By("Creating a CertificateSigningRequest")
			csr, pk, err := gen.CSR(x509.RSA,
				gen.SetCSRDNSNames(exampleDNSNames...),
				gen.SetCSRIPAddresses(exampleIPAddresses...),
				gen.SetCSRURIs(exampleURLs()...),
			)
			Expect(err).NotTo(HaveOccurred())

			kubeCSR := gen.CertificateSigningRequest("",
				gen.SetCertificateSigningRequestDuration("2160h"),
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/"+f.Namespace.Name+"."+issuerName),
				gen.SetCertificateSigningRequestRequest(csr),
				gen.SetCertificateSigningRequestUsages([]certificatesv1.KeyUsage{
					certificatesv1.UsageKeyEncipherment,
					certificatesv1.UsageDigitalSignature,
				}),
			)
			kubeCSR.GenerateName = "test-ca-certificatesigningrequest-"
			kubeCSR, err = csrClient.Create(context.TODO(), kubeCSR, metav1.CreateOptions{})
			kubeCSRName = kubeCSR.Name
			Expect(err).NotTo(HaveOccurred())

			By("Approving CertificateSigningRequest")
			kubeCSR.Status.Conditions = append(kubeCSR.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
				Type:    certificatesv1.CertificateApproved,
				Status:  corev1.ConditionTrue,
				Reason:  "e2e.cert-manager.io",
				Message: "Approved for e2e testing",
			})
			_, err = csrClient.UpdateApproval(context.TODO(), kubeCSR.Name, kubeCSR, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the certificate is valid")
			err = h.WaitCertificateSigningRequestIssuedValidTLS(f.Namespace.Name, kubeCSR.Name, time.Second*30, pk, []byte(rootCert))
			Expect(err).NotTo(HaveOccurred())
		})

		It("should be able to obtain an ECDSA key from a RSA backed issuer", func() {
			csrClient := f.KubeClientSet.CertificatesV1().CertificateSigningRequests()

			By("Creating a CertificateSigningRequest")
			csr, pk, err := gen.CSR(x509.ECDSA,
				gen.SetCSRDNSNames(exampleDNSNames...),
				gen.SetCSRIPAddresses(exampleIPAddresses...),
				gen.SetCSRURIs(exampleURLs()...),
			)
			Expect(err).NotTo(HaveOccurred())

			kubeCSR := gen.CertificateSigningRequest("",
				gen.SetCertificateSigningRequestDuration("2160h"),
				gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/"+f.Namespace.Name+"."+issuerName),
				gen.SetCertificateSigningRequestRequest(csr),
				gen.SetCertificateSigningRequestUsages([]certificatesv1.KeyUsage{
					certificatesv1.UsageKeyEncipherment,
					certificatesv1.UsageDigitalSignature,
				}),
			)
			kubeCSR.GenerateName = "test-ca-certificatesigningrequest-"
			kubeCSR, err = csrClient.Create(context.TODO(), kubeCSR, metav1.CreateOptions{})
			kubeCSRName = kubeCSR.Name
			Expect(err).NotTo(HaveOccurred())

			By("Approving CertificateSigningRequest")
			kubeCSR.Status.Conditions = append(kubeCSR.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
				Type:    certificatesv1.CertificateApproved,
				Status:  corev1.ConditionTrue,
				Reason:  "e2e.cert-manager.io",
				Message: "Approved for e2e testing",
			})
			_, err = csrClient.UpdateApproval(context.TODO(), kubeCSR.Name, kubeCSR, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the certificate is valid")
			err = h.WaitCertificateSigningRequestIssuedValidTLS(f.Namespace.Name, kubeCSR.Name, time.Second*30, pk, []byte(rootCert))
			Expect(err).NotTo(HaveOccurred())
		})

		cases := []struct {
			inputDuration    string
			expectedDuration time.Duration
			label            string
		}{
			{
				inputDuration:    "840h",
				expectedDuration: time.Hour * 24 * 35,
				label:            "35 days",
			},
			{
				inputDuration:    "",
				expectedDuration: time.Hour * 24 * 90,
				label:            "the default duration (90 days)",
			},
		}
		for _, v := range cases {
			v := v
			It("should generate a signed certificate valid for "+v.label, func() {
				csrClient := f.KubeClientSet.CertificatesV1().CertificateSigningRequests()

				By("Creating a CertificateSigningRequest")
				csr, pk, err := gen.CSR(x509.RSA,
					gen.SetCSRDNSNames(exampleDNSNames...),
					gen.SetCSRIPAddresses(exampleIPAddresses...),
					gen.SetCSRURIs(exampleURLs()...),
				)
				Expect(err).NotTo(HaveOccurred())

				kubeCSR := gen.CertificateSigningRequest("",
					gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/"+f.Namespace.Name+"."+issuerName),
					gen.SetCertificateSigningRequestRequest(csr),
					gen.SetCertificateSigningRequestUsages([]certificatesv1.KeyUsage{
						certificatesv1.UsageKeyEncipherment,
						certificatesv1.UsageDigitalSignature,
					}),
				)

				if len(v.inputDuration) > 0 {
					kubeCSR.Annotations[experimentalapi.CertificateSigningRequestDurationAnnotationKey] = v.inputDuration
				}

				kubeCSR.GenerateName = "test-ca-certificatesigningrequest-"
				kubeCSR, err = csrClient.Create(context.TODO(), kubeCSR, metav1.CreateOptions{})
				kubeCSRName = kubeCSR.Name
				Expect(err).NotTo(HaveOccurred())

				By("Approving CertificateSigningRequest")
				kubeCSR.Status.Conditions = append(kubeCSR.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
					Type:    certificatesv1.CertificateApproved,
					Status:  corev1.ConditionTrue,
					Reason:  "e2e.cert-manager.io",
					Message: "Approved for e2e testing",
				})
				_, err = csrClient.UpdateApproval(context.TODO(), kubeCSR.Name, kubeCSR, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying the certificate is valid")
				err = h.WaitCertificateSigningRequestIssuedValidTLS(f.Namespace.Name, kubeCSR.Name, time.Second*30, pk, []byte(rootCert))
				Expect(err).NotTo(HaveOccurred())

				kubeCSR, err = csrClient.Get(context.TODO(), kubeCSR.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				err = f.Helper().CertificateSigningRequestDurationValid(kubeCSR, v.expectedDuration, 0)
				Expect(err).NotTo(HaveOccurred())
			})
		}
	})
})
