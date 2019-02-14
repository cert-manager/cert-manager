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

package certificate

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = framework.CertManagerDescribe("Self Signed Certificate", func() {
	f := framework.NewDefaultFramework("create-selfsigned-certificate")
	h := f.Helper()

	issuerName := "test-selfsigned-issuer"
	certificateName := "test-selfsigned-certificate"
	certificateSecretName := "test-selfsigned-certificate"

	It("should generate a signed keypair", func() {
		By("Creating an Issuer")

		certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)

		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(util.NewCertManagerSelfSignedIssuer(issuerName))
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			issuerName,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
		By("Creating a Certificate")
		_, err = certClient.Create(util.NewCertManagerBasicCertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind, nil, nil))
		Expect(err).NotTo(HaveOccurred())
		err = h.WaitCertificateIssuedValid(f.Namespace.Name, certificateName, time.Minute*5)
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

			By("Creating an Issuer")
			issuerDurationName := fmt.Sprintf("%s-%d", issuerName, v.expectedDuration)
			_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(util.NewCertManagerSelfSignedIssuer(issuerDurationName))
			Expect(err).NotTo(HaveOccurred())
			By("Waiting for Issuer to become Ready")
			err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
				issuerDurationName,
				v1alpha1.IssuerCondition{
					Type:   v1alpha1.IssuerConditionReady,
					Status: v1alpha1.ConditionTrue,
				})
			Expect(err).NotTo(HaveOccurred())

			By("Creating a Certificate")
			cert, err := certClient.Create(util.NewCertManagerBasicCertificate(certificateName, certificateSecretName, issuerDurationName, v1alpha1.IssuerKind, v.inputDuration, v.inputRenewBefore))
			Expect(err).NotTo(HaveOccurred())
			err = h.WaitCertificateIssuedValid(f.Namespace.Name, certificateName, time.Second*30)
			Expect(err).NotTo(HaveOccurred())
			f.CertificateDurationValid(cert, v.expectedDuration)
		})
	}
})
