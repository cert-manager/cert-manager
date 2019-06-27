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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	stepaddon "github.com/jetstack/cert-manager/test/e2e/framework/addon/step"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	"github.com/jetstack/cert-manager/test/e2e/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = framework.CertManagerDescribe("Step Certificate", func() {
	f := framework.NewDefaultFramework("create-step-certificate")
	h := f.Helper()

	var (
		tiller = &tiller.Tiller{
			Name:               "tiller-deploy",
			ClusterPermissions: false,
		}
		step = &stepaddon.Step{
			Tiller: tiller,
			Name:   "cm-e2e-create-step-certificate",
		}
	)

	BeforeEach(func() {
		tiller.Namespace = f.Namespace.Name
		step.Namespace = f.Namespace.Name
	})

	f.RequireAddon(tiller)
	f.RequireAddon(step)

	issuerName := "test-step-issuer"
	certificateName := "test-step-certificate"
	certificateSecretName := "test-step-certificate"

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(issuerName, nil)
	})

	It("should generate a new valid certificate", func() {
		s := step.Details()
		By("Creating an Issuer")
		stepIssuer := util.NewCertManagerStepIssuer(issuerName, s.Host, s.ProvisionerName, s.ProvisionerKeyID, s.ProvisionerPasswordRef, s.ProvisionerPasswordKey, s.CABundle)
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(stepIssuer)
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			stepIssuer.Name,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())

		By("Creating a Certificate")
		certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)
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
		event            string
	}{
		{
			inputDuration:    nil,
			inputRenewBefore: nil,
			expectedDuration: 24 * time.Hour,
			label:            "valid for 24 hours (default)",
		},
		{
			inputDuration:    &metav1.Duration{90 * 24 * time.Hour},
			inputRenewBefore: nil,
			expectedDuration: 90 * 24 * time.Hour,
			label:            "valid for 90 days",
		},
		{
			// extra 30 seconds to avoid bug with duration limits on some
			// step-certificate versions
			inputDuration:    &metav1.Duration{time.Hour + 30*time.Second},
			inputRenewBefore: &metav1.Duration{5 * time.Minute},
			expectedDuration: time.Hour + 30*time.Second,
			label:            "valid for 1 hour with renew before 5 minutes",
		},
		{
			inputDuration:    &metav1.Duration{24 * time.Hour},
			inputRenewBefore: &metav1.Duration{8 * time.Hour},
			expectedDuration: 24 * time.Hour,
			label:            "valid for 24 hours and renew before 8 hours",
		},
	}

	for _, v := range cases {
		v := v
		It("should generate a new certificate "+v.label, func() {
			s := step.Details()
			By("Creating an Issuer")
			stepIssuer := util.NewCertManagerStepIssuer(issuerName, s.Host, s.ProvisionerName, s.ProvisionerKeyID, s.ProvisionerPasswordRef, s.ProvisionerPasswordKey, s.CABundle)
			_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(stepIssuer)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for Issuer to become Ready")
			err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
				stepIssuer.Name,
				v1alpha1.IssuerCondition{
					Type:   v1alpha1.IssuerConditionReady,
					Status: v1alpha1.ConditionTrue,
				})
			Expect(err).NotTo(HaveOccurred())

			By("Creating a Certificate")
			certClient := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name)
			cert, err := certClient.Create(util.NewCertManagerBasicCertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind, v.inputDuration, v.inputRenewBefore))
			Expect(err).NotTo(HaveOccurred())

			err = h.WaitCertificateIssuedValid(f.Namespace.Name, certificateName, time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			f.CertificateDurationValid(cert, v.expectedDuration)
		})
	}
})
