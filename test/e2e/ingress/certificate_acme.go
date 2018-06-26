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

package ingress

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/util"
)

const testingACMEEmail = "test@example.com"
const testingACMEPrivateKey = "test-acme-private-key"
const foreverTestTimeout = time.Second * 60

var _ = framework.CertManagerDescribe("ACME Certificate with Ingress (HTTP01)", func() {
	f := framework.NewDefaultFramework("create-acme-certificate-http01-ingress")

	issuerName := "test-acme-issuer"
	certificateSecretName := "test-acme-certificate"

	BeforeEach(func() {
		By("Verifying there is no existing ACME private key")
		_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(testingACMEPrivateKey, metav1.GetOptions{})
		Expect(err).To(MatchError(apierrors.NewNotFound(corev1.Resource("secrets"), testingACMEPrivateKey)))
		By("Verifying there is no existing TLS certificate secret")
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(certificateSecretName, metav1.GetOptions{})
		Expect(err).To(MatchError(apierrors.NewNotFound(corev1.Resource("secrets"), certificateSecretName)))
		By("Creating an Issuer")
		_, err = f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(util.NewCertManagerACMEIssuer(issuerName, framework.TestContext.ACMEURL, testingACMEEmail, testingACMEPrivateKey, 0, 0))
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			issuerName,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
		By("Verifying the ACME account URI is set")
		err = util.WaitForIssuerStatusFunc(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			issuerName,
			func(i *v1alpha1.Issuer) (bool, error) {
				if i.GetStatus().ACMEStatus().URI == "" {
					return false, nil
				}
				return true, nil
			})
		Expect(err).NotTo(HaveOccurred())
		By("Verifying ACME account private key exists")
		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(testingACMEPrivateKey, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		if len(secret.Data) != 1 {
			Fail("Expected 1 key in ACME account private key secret, but there was %d", len(secret.Data))
		}
	})

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(issuerName, nil)
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(testingACMEPrivateKey, nil)
	})

	It("should obtain a signed certificate with a single CN from the ACME server when putting an annotation on an ingress resource", func() {
		By("Creating an Ingress with the issuer name annotation set")
		_, err := f.KubeClientSet.ExtensionsV1beta1().Ingresses(f.Namespace.Name).Create(util.NewIngress(certificateSecretName, certificateSecretName, map[string]string{
			"certmanager.k8s.io/issuer":                  issuerName,
			"certmanager.k8s.io/acme-challenge-provider": "http01",
		}, util.ACMECertificateDomain))
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Certificate to exist")
		err = util.WaitForCertificateToExist(f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name), certificateSecretName, foreverTestTimeout)
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Certificate to become Ready")
		err = util.WaitForCertificateCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name),
			certificateSecretName,
			v1alpha1.CertificateCondition{
				Type:   v1alpha1.CertificateConditionReady,
				Status: v1alpha1.ConditionTrue,
			}, foreverTestTimeout)
		Expect(err).NotTo(HaveOccurred())
		By("Verifying TLS certificate exists")
		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(certificateSecretName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		if len(secret.Data) != 2 {
			Fail("Expected 2 keys in ACME certificate secret, but there was %d", len(secret.Data))
		}
	})

})
