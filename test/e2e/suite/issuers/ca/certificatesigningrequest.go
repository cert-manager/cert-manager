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
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/util"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

// The tests in this file require that the CertificateSigningRequest
// controllers are active
// (--feature-gates=ExperimentalCertificateSigningRequestControllers=true). If
// they are not active, these tests will fail.
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
	})

	Context("create valid signed certificates", func() {
		BeforeEach(func() {
			By("Creating a signing keypair fixture")
			_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), newSigningKeypairSecret(issuerSecretName), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		cases := map[string]struct {
			keyAlg           x509.PublicKeyAlgorithm
			csrMods          []gen.CSRModifier
			kubeCSRMods      []gen.CertificateSigningRequestModifier
			expectedDuration time.Duration
		}{
			"rsa with 2160h duration": {
				keyAlg: x509.RSA,
				csrMods: []gen.CSRModifier{
					gen.SetCSRDNSNames(exampleDNSNames...),
					gen.SetCSRIPAddresses(exampleIPAddresses...),
					gen.SetCSRURIs(exampleURLs()...),
				},
				kubeCSRMods: []gen.CertificateSigningRequestModifier{
					gen.SetCertificateSigningRequestDuration("2160h"),
					gen.SetCertificateSigningRequestUsages([]certificatesv1.KeyUsage{
						certificatesv1.UsageKeyEncipherment,
						certificatesv1.UsageDigitalSignature,
						certificatesv1.UsageServerAuth,
					}),
				},
				expectedDuration: time.Hour * 2160,
			},
			"ecdsa with 2160h duration": {
				keyAlg: x509.ECDSA,
				csrMods: []gen.CSRModifier{
					gen.SetCSRDNSNames(exampleDNSNames...),
					gen.SetCSRIPAddresses(exampleIPAddresses...),
					gen.SetCSRURIs(exampleURLs()...),
				},
				kubeCSRMods: []gen.CertificateSigningRequestModifier{
					gen.SetCertificateSigningRequestDuration("2160h"),
					gen.SetCertificateSigningRequestUsages([]certificatesv1.KeyUsage{
						certificatesv1.UsageKeyEncipherment,
						certificatesv1.UsageDigitalSignature,
						certificatesv1.UsageServerAuth,
					}),
				},
				expectedDuration: time.Hour * 2160,
			},
			"rsa with default duration should be 90 days duration": {
				keyAlg: x509.ECDSA,
				csrMods: []gen.CSRModifier{
					gen.SetCSRDNSNames(exampleDNSNames...),
					gen.SetCSRIPAddresses(exampleIPAddresses...),
					gen.SetCSRURIs(exampleURLs()...),
				},
				kubeCSRMods: []gen.CertificateSigningRequestModifier{
					gen.SetCertificateSigningRequestUsages([]certificatesv1.KeyUsage{
						certificatesv1.UsageKeyEncipherment,
						certificatesv1.UsageDigitalSignature,
						certificatesv1.UsageServerAuth,
					}),
				},
				expectedDuration: time.Hour * 24 * 90,
			},
			"ecdsa with default duration and custom usages and CA": {
				keyAlg: x509.ECDSA,
				csrMods: []gen.CSRModifier{
					gen.SetCSRDNSNames(exampleDNSNames...),
					gen.SetCSRIPAddresses(exampleIPAddresses...),
					gen.SetCSRURIs(exampleURLs()...),
				},
				kubeCSRMods: []gen.CertificateSigningRequestModifier{
					gen.SetCertificateSigningRequestIsCA(true),
					gen.SetCertificateSigningRequestUsages([]certificatesv1.KeyUsage{
						certificatesv1.UsageKeyEncipherment,
						certificatesv1.UsageDigitalSignature,
						certificatesv1.UsageCRLSign,
						certificatesv1.UsageCertSign,
						certificatesv1.UsageOCSPSigning,
						certificatesv1.UsageServerAuth,
					}),
				},
				expectedDuration: time.Hour * 24 * 90,
			},
		}

		for name, tcase := range cases {
			It("should generate a signed certificate valid for: "+name, func() {
				csrClient := f.KubeClientSet.CertificatesV1().CertificateSigningRequests()

				By("Creating a CertificateSigningRequest")
				csr, pk, err := gen.CSR(tcase.keyAlg, tcase.csrMods...)
				Expect(err).NotTo(HaveOccurred())

				kubeCSR := gen.CertificateSigningRequest("",
					append(
						tcase.kubeCSRMods,
						gen.SetCertificateSigningRequestRequest(csr),
						gen.SetCertificateSigningRequestSignerName("issuers.cert-manager.io/"+f.Namespace.Name+"."+issuerName),
					)...,
				)
				kubeCSR.GenerateName = "test-ca-certificatesigningrequest-"
				kubeCSR, err = csrClient.Create(context.TODO(), kubeCSR, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				defer f.KubeClientSet.CertificatesV1().CertificateSigningRequests().Delete(context.TODO(), kubeCSR.Name, metav1.DeleteOptions{})

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
				err = f.Helper().CertificateSigningRequestDurationValid(kubeCSR, tcase.expectedDuration, 0)
				Expect(err).NotTo(HaveOccurred())
			})
		}
	})
})
