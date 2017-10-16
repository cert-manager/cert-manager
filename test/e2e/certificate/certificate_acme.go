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

package certificate

import (
	"flag"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	cmutil "github.com/jetstack-experimental/cert-manager/pkg/util"
	"github.com/jetstack-experimental/cert-manager/test/e2e/framework"
	"github.com/jetstack-experimental/cert-manager/test/util"
)

const testingACMEURL = "http://127.0.0.1:4000/directory"
const invalidACMEURL = "http://not-a-real-acme-url.com"
const testingACMEEmail = "test@example.com"
const testingACMEPrivateKey = "test-acme-private-key"

var acmeCertificateDomain string
var acmeIngressClass string

func init() {
	flag.StringVar(&acmeCertificateDomain, "acme-nginx-certificate-domain", "",
		"The provided domain and all sub-domains should resolve to the nginx ingress controller")
	flag.StringVar(&acmeIngressClass, "acme-nginx-ingress-class", "nginx", ""+
		"The ingress class for the nginx ingress controller")
}

var _ = framework.CertManagerDescribe("ACME Certificate (HTTP01)", func() {
	f := framework.NewDefaultFramework("create-acme-certificate-http01")

	issuerName := "test-acme-issuer"
	certificateName := "test-acme-certificate"
	certificateSecretName := "test-acme-certificate"

	BeforeEach(func() {
		By("Creating an Issuer")
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(util.NewCertManagerACMEIssuer(issuerName, testingACMEURL, testingACMEEmail, testingACMEPrivateKey))
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
		By("Deleting the Issuer")
		err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(issuerName, nil)
		Expect(err).NotTo(HaveOccurred())
		By("Deleting the ACME account private key")
		err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(testingACMEPrivateKey, nil)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should obtain a signed certificate with a single CN from the ACME server", func() {
		By("Creating a Certificate")
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name).Create(util.NewCertManagerACMECertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind, acmeIngressClass, acmeCertificateDomain))
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Certificate to become Ready")
		err = util.WaitForCertificateCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name),
			certificateName,
			v1alpha1.CertificateCondition{
				Type:   v1alpha1.CertificateConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should obtain a signed certificate with a CN and single subdomain as dns name from the ACME server", func() {
		By("Creating a Certificate")
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name).Create(util.NewCertManagerACMECertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind, acmeIngressClass, acmeCertificateDomain, fmt.Sprintf("%s.%s", cmutil.RandStringRunes(5), acmeCertificateDomain)))
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Certificate to become Ready")
		err = util.WaitForCertificateCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name),
			certificateName,
			v1alpha1.CertificateCondition{
				Type:   v1alpha1.CertificateConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should fail to obtain a certificate for an invalid ACME dns name", func() {
		By("Creating a Certificate")
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name).Create(util.NewCertManagerACMECertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind, acmeIngressClass, "google.com"))
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for the Certificate to not have a ready condition")
		err = util.WaitForCertificateCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name),
			certificateName,
			v1alpha1.CertificateCondition{
				Type:   v1alpha1.CertificateConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).To(HaveOccurred())
	})
})
