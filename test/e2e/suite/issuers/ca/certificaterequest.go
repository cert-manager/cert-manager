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
	"crypto/x509"
	"net"
	"net/url"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/e2e-tests/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func exampleURLs() (urls []*url.URL) {
	a, _ := url.Parse("spiffe://foo.foo.example.net")
	b, _ := url.Parse("spiffe://foo.bar.example.net")
	urls = append(urls, a, b)
	return
}

var _ = framework.CertManagerDescribe("CA CertificateRequest", func() {
	ctx := context.TODO()
	f := framework.NewDefaultFramework("create-ca-certificate")
	h := f.Helper()

	issuerName := "test-ca-issuer"
	issuerSecretName := "ca-issuer-signing-keypair"
	certificateRequestName := "test-ca-certificaterequest"

	exampleDNSNames := []string{"dnsName1.co", "dnsName2.ninja"}
	exampleIPAddresses := []net.IP{
		[]byte{8, 8, 8, 8},
		[]byte{1, 1, 1, 1},
	}
	exampleURIs := []string{"spiffe://foo.foo.example.net", "spiffe://foo.bar.example.net"}

	JustBeforeEach(func() {
		By("Creating an Issuer")
		issuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerCASecretName(issuerSecretName))
		_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, issuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Cleaning up")
		err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(ctx, issuerSecretName, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
		err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(ctx, issuerName, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	Context("when the CA is the root", func() {
		BeforeEach(func() {
			By("Creating a signing keypair fixture")
			_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(ctx, newSigningKeypairSecret(issuerSecretName), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should generate a valid certificate from CSR", func() {
			certRequestClient := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name)

			By("Creating a CertificateRequest")
			cr, key, err := util.NewCertManagerBasicCertificateRequest(certificateRequestName, f.Namespace.Name, issuerName, v1.IssuerKind,
				&metav1.Duration{
					Duration: time.Hour * 24 * 90,
				},
				exampleDNSNames, exampleIPAddresses, exampleURIs, x509.RSA)
			Expect(err).NotTo(HaveOccurred())
			_, err = certRequestClient.Create(ctx, cr, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			By("Verifying the Certificate is valid")
			err = h.WaitCertificateRequestIssuedValidTLS(ctx, f.Namespace.Name, certificateRequestName, time.Second*30, key, []byte(rootCert))
			Expect(err).NotTo(HaveOccurred())
		})

		It("should be able to obtain an ECDSA key from a RSA backed issuer", func() {
			certRequestClient := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name)

			By("Creating a CertificateRequest")
			cr, key, err := util.NewCertManagerBasicCertificateRequest(certificateRequestName, f.Namespace.Name, issuerName, v1.IssuerKind,
				&metav1.Duration{
					Duration: time.Hour * 24 * 90,
				},
				exampleDNSNames, exampleIPAddresses, exampleURIs, x509.ECDSA)
			Expect(err).NotTo(HaveOccurred())
			_, err = certRequestClient.Create(ctx, cr, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			By("Verifying the Certificate is valid")
			err = h.WaitCertificateRequestIssuedValidTLS(ctx, f.Namespace.Name, certificateRequestName, time.Second*30, key, []byte(rootCert))
			Expect(err).NotTo(HaveOccurred())
		})

		It("should be able to obtain an Ed25519 key from a RSA backed issuer", func() {
			certRequestClient := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name)

			By("Creating a CertificateRequest")
			cr, key, err := util.NewCertManagerBasicCertificateRequest(certificateRequestName, f.Namespace.Name, issuerName, v1.IssuerKind,
				&metav1.Duration{
					Duration: time.Hour * 24 * 90,
				},
				exampleDNSNames, exampleIPAddresses, exampleURIs, x509.Ed25519)
			Expect(err).NotTo(HaveOccurred())
			_, err = certRequestClient.Create(ctx, cr, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			By("Verifying the Certificate is valid")
			err = h.WaitCertificateRequestIssuedValidTLS(ctx, f.Namespace.Name, certificateRequestName, time.Second*30, key, []byte(rootCert))
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

				By("Creating a CertificateRequest with Usages")
				csr, key, err := gen.CSR(x509.RSA, gen.SetCSRDNSNames(exampleDNSNames...), gen.SetCSRIPAddresses(exampleIPAddresses...), gen.SetCSRURIs(exampleURLs()...))
				Expect(err).NotTo(HaveOccurred())
				cr := gen.CertificateRequest(certificateRequestName, gen.SetCertificateRequestNamespace(f.Namespace.Name), gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Kind: v1.IssuerKind, Name: issuerName}), gen.SetCertificateRequestDuration(v.inputDuration), gen.SetCertificateRequestCSR(csr))
				cr, err = crClient.Create(ctx, cr, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying the CertificateRequest is valid")
				err = h.WaitCertificateRequestIssuedValid(ctx, f.Namespace.Name, certificateRequestName, time.Second*30, key)
				Expect(err).NotTo(HaveOccurred())
				cr, err = crClient.Get(ctx, cr.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				f.CertificateRequestDurationValid(cr, v.expectedDuration, 0)
			})
		}
	})
})
