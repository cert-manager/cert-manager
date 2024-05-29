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
	"fmt"
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

var _ = framework.CertManagerDescribe("Self Signed Certificate", func() {
	ctx := context.TODO()
	f := framework.NewDefaultFramework("create-selfsigned-certificate")

	issuerName := "test-selfsigned-issuer"
	certificateName := "test-selfsigned-certificate"
	certificateSecretName := "test-selfsigned-certificate"

	It("should generate a signed keypair", func() {
		By("Creating an Issuer")

		certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

		issuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerSelfSigned(v1.SelfSignedIssuer{}))
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
		By("Creating a Certificate")
		cert := gen.Certificate(certificateName,
			gen.SetCertificateNamespace(f.Namespace.Name),
			gen.SetCertificateSecretName(certificateSecretName),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{
				Name: issuerName,
				Kind: v1.IssuerKind,
			}),
			gen.SetCertificateCommonName("test.domain.com"),
			gen.SetCertificateOrganization("test-org"),
		)
		cert, err = certClient.Create(ctx, cert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for the Certificate to be issued...")
		cert, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, cert, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Validating the issued Certificate...")
		err = f.Helper().ValidateCertificate(cert)
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

			By("Creating an Issuer")
			issuerDurationName := fmt.Sprintf("%s-%d", issuerName, v.expectedDuration)
			issuer := gen.Issuer(issuerDurationName,
				gen.SetIssuerNamespace(f.Namespace.Name),
				gen.SetIssuerSelfSigned(v1.SelfSignedIssuer{}))
			_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, issuer, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			By("Waiting for Issuer to become Ready")
			err = util.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
				issuerDurationName,
				v1.IssuerCondition{
					Type:   v1.IssuerConditionReady,
					Status: cmmeta.ConditionTrue,
				})
			Expect(err).NotTo(HaveOccurred())

			By("Creating a Certificate")
			cert := gen.Certificate(certificateName,
				gen.SetCertificateNamespace(f.Namespace.Name),
				gen.SetCertificateSecretName(certificateSecretName),
				gen.SetCertificateIssuer(cmmeta.ObjectReference{
					Name: issuerDurationName,
					Kind: v1.IssuerKind,
				}),
				gen.SetCertificateDuration(v.inputDuration),
				gen.SetCertificateRenewBefore(v.inputRenewBefore),
				gen.SetCertificateCommonName("test.domain.com"),
				gen.SetCertificateOrganization("test-org"),
			)
			cert, err = certClient.Create(ctx, cert, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			By("Waiting for the Certificate to be issued...")
			cert, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, cert, time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(cert)
			Expect(err).NotTo(HaveOccurred())

			f.CertificateDurationValid(ctx, cert, v.expectedDuration, 0)
		})
	}

	It("should correctly encode a certificate's private key based on the key encoding", func() {
		By("Creating an Issuer")

		certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

		issuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerSelfSigned(v1.SelfSignedIssuer{}))
		_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, issuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Creating a Certificate")
		cert := gen.Certificate(certificateName,
			gen.SetCertificateNamespace(f.Namespace.Name),
			gen.SetCertificateSecretName(certificateSecretName),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{
				Name: issuerName,
				Kind: v1.IssuerKind,
			}),
			gen.SetCertificateCommonName("test.domain.com"),
			gen.SetCertificateOrganization("test-org"),
			gen.SetCertificateKeyEncoding(v1.PKCS8),
		)
		cert, err = certClient.Create(ctx, cert, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be issued...")
		cert, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, cert, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Validating the issued Certificate...")
		err = f.Helper().ValidateCertificate(cert)
		Expect(err).NotTo(HaveOccurred())
	})
})
