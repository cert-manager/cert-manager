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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/util"
	"github.com/jetstack/cert-manager/test/util/cfssl"
)

var _ = framework.CertManagerDescribe("CFSSL Issuer", func() {
	f := framework.NewDefaultFramework("create-cfssl-issuer")

	issuerName := "test-cfssl-issuer"
	serverURL := "http://cfssl.cfssl:8080"
	serverPath := "/api/v1/cfssl/authsign"

	issuerAuthKeySecret := "C0DEC0DEC0DEC0DEC0DEC0DE"
	issuerAuthKeySecretName := "test-cfssl-authkey"

	BeforeEach(func() {
		By("Creating a authkey secret fixture")
		_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(cfssl.NewAuthKeySecret(issuerAuthKeySecretName, issuerAuthKeySecret))
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(issuerName, nil)
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(issuerAuthKeySecretName, nil)
	})

	It("should be ready with a valid serverurl and serverpath and missing authkey", func() {
		By("Creating an Issuer")
		issuer := util.NewCertManagerCFSSLIssuer(issuerName, serverURL, serverPath, issuerAuthKeySecretName)
		issuer.Spec.IssuerConfig.CFSSL.AuthKey = nil

		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(issuer)
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

	It("should be ready with a valid serverurl, serverpath and authkey", func() {
		By("Creating an Issuer")
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(util.NewCertManagerCFSSLIssuer(issuerName, serverURL, serverPath, issuerAuthKeySecretName))
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

	It("should fail to init with missing serverurl", func() {
		By("Creating an Issuer with empty serverurl")
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(util.NewCertManagerCFSSLIssuer(issuerName, "", serverPath, issuerAuthKeySecretName))
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			issuerName,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should fail to init with missing serverpath", func() {
		By("Creating an Issuer with empty serverpath")
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(util.NewCertManagerCFSSLIssuer(issuerName, serverURL, "", issuerAuthKeySecretName))
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			issuerName,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())
	})
})
