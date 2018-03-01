/*
Copyright 2017 Jetstack Ltd.
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

package issuer

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/util"
)

var _ = framework.CertManagerDescribe("CA Issuer", func() {
	f := framework.NewDefaultFramework("create-ca-issuer")

	issuerName := "test-ca-issuer"
	secretName := "ca-issuer-signing-keypair"

	BeforeEach(func() {
		By("Creating a signing keypair fixture")
		_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(util.NewSigningKeypairSecret(secretName))
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Cleaning up")
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(secretName, nil)
	})

	It("should generate a signing keypair", func() {
		By("Creating an Issuer")
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(util.NewCertManagerCAIssuer(issuerName, secretName, 0, 0))
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

	cases := []struct {
		inputDuration    time.Duration
		inputRenewBefore time.Duration
		label            string
		status           v1alpha1.ConditionStatus
	}{
		{
			inputDuration:    0,
			inputRenewBefore: time.Hour * 24 * 365 * 10,
			label:            "should fail when renewBefore is bigger than the duration",
			status:           v1alpha1.ConditionStatus(v1alpha1.ConditionFalse),
		},
		{
			inputDuration:    0,
			inputRenewBefore: time.Second,
			label:            "should fail when renewBefore is less than the minimum permitted value",
			status:           v1alpha1.ConditionStatus(v1alpha1.ConditionFalse),
		},
		{
			inputDuration:    time.Second,
			inputRenewBefore: 0,
			label:            "should fail when duration is less than the minimum permitted value",
			status:           v1alpha1.ConditionStatus(v1alpha1.ConditionFalse),
		},
	}

	for _, v := range cases {
		v := v
		It(v.label, func() {
			issuerName := "test-issuer-duration"

			By("Creating an Issuer")
			_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(util.NewCertManagerCAIssuer(issuerName, secretName, v.inputDuration, v.inputRenewBefore))
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for Issuer to become Ready")
			err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
				issuerName,
				v1alpha1.IssuerCondition{
					Type:   v1alpha1.IssuerConditionReady,
					Status: v.status,
				})
			Expect(err).NotTo(HaveOccurred())

			By("Cleaning up")
			f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(issuerName, nil)
		})
	}
})
