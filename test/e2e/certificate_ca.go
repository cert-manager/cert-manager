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

var _ = framework.CertManagerDescribe("CA Certificate", func() {
	f := framework.NewDefaultFramework("create-ca-certificate")

	podName := "test-cert-manager"
	issuerName := "test-ca-issuer"
	issuerSecretName := "ca-issuer-signing-keypair"
	certificateName := "test-ca-certificate"
	certificateSecretName := "test-ca-certificate"

	BeforeEach(func() {
		By("Creating a cert-manager pod")
		pod, err := f.KubeClientSet.CoreV1().Pods(f.Namespace.Name).Create(NewCertManagerControllerPod(podName, "--cluster-resource-namespace="+f.Namespace.Name))
		Expect(err).NotTo(HaveOccurred())
		err = framework.WaitForPodRunningInNamespace(f.KubeClientSet, pod)
		Expect(err).NotTo(HaveOccurred())
		By("Creating a signing keypair fixture")
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(newSigningKeypairSecret(issuerSecretName))
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Deleting the cert-manager pod")
		err := f.KubeClientSet.CoreV1().Pods(f.Namespace.Name).Delete(podName, nil)
		Expect(err).NotTo(HaveOccurred())
		err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(issuerSecretName, nil)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should generate a signed keypair", func() {
		By("Creating an Issuer")
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(newCertManagerCAIssuer(issuerName, issuerSecretName))
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
		_, err = f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name).Create(newCertManagerCACertificate(certificateName, certificateSecretName, issuerName, v1alpha1.IssuerKind))
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

	It("should generate a signed keypair from a clusterissuer", func() {
		By("Creating a ClusterIssuer")
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().ClusterIssuers().Create(newCertManagerCAClusterIssuer(issuerName, issuerSecretName))
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for ClusterIssuer to become Ready")
		err = util.WaitForClusterIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().ClusterIssuers(),
			issuerName,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
		By("Creating a Certificate")
		_, err = f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name).Create(newCertManagerCACertificate(certificateName, certificateSecretName, issuerName, v1alpha1.ClusterIssuerKind))
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
})

func newCertManagerCACertificate(name, secretName, issuerName string, issuerKind string) *v1alpha1.Certificate {
	return &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.CertificateSpec{
			Domains: []string{
				"test.domain.com",
			},
			SecretName: secretName,
			IssuerRef: v1alpha1.ObjectReference{
				Name: issuerName,
				Kind: issuerKind,
			},
		},
	}
}
