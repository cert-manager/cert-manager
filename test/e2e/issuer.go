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

package e2e

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack-experimental/cert-manager/test/e2e/framework"
	"github.com/jetstack-experimental/cert-manager/test/util"
)

var _ = framework.CertManagerDescribe("Issuer", func() {
	f := framework.NewDefaultFramework("create-issuer")

	podName := "test-cert-manager"
	issuerName := "test-acme-issuer"

	BeforeEach(func() {
		By("Creating a cert-manager pod")
		pod, err := f.KubeClientSet.CoreV1().Pods(f.Namespace.Name).Create(NewCertManagerControllerPod(podName))
		Expect(err).NotTo(HaveOccurred())
		err = framework.WaitForPodRunningInNamespace(f.KubeClientSet, pod)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Deleting the cert-manager pod")
		err := f.KubeClientSet.CoreV1().Pods(f.Namespace.Name).Delete(podName, nil)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should register ACME account", func() {
		By("Creating an Issuer")
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(newCertManagerACMEIssuer(issuerName, testingACMEURL, testingACMEEmail, testingACMEPrivateKey))
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerReady(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name), issuerName)
		Expect(err).NotTo(HaveOccurred())
	})
})

const testingACMEURL = "https://acme-staging.api.letsencrypt.org/directory"
const testingACMEEmail = "test@example.com"
const testingACMEPrivateKey = "test-acme-private-key"

func newCertManagerACMEIssuer(name, acmeURL, acmeEmail, acmePrivateKey string) *v1alpha1.Issuer {
	return &v1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.IssuerSpec{
			ACME: &v1alpha1.ACMEIssuer{
				Email:      acmeEmail,
				Server:     acmeURL,
				PrivateKey: acmePrivateKey,
			},
		},
	}
}
