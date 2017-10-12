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

package clusterissuer

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack-experimental/cert-manager/test/e2e/framework"
	"github.com/jetstack-experimental/cert-manager/test/util"
)

var _ = framework.CertManagerDescribe("CA ClusterIssuer", func() {
	f := framework.NewDefaultFramework("create-ca-clusterissuer")

	podName := "test-cert-manager"
	issuerName := "test-ca-clusterissuer"
	secretName := "ca-clusterissuer-signing-keypair"

	BeforeEach(func() {
		By("Creating a cert-manager pod")
		pod, err := f.KubeClientSet.CoreV1().Pods(f.Namespace.Name).Create(util.NewCertManagerControllerPod(podName, "--cluster-resource-namespace="+f.Namespace.Name))
		Expect(err).NotTo(HaveOccurred())
		err = framework.WaitForPodRunningInNamespace(f.KubeClientSet, pod)
		Expect(err).NotTo(HaveOccurred())
		By("Creating a signing keypair fixture")
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(util.NewSigningKeypairSecret(secretName))
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Deleting the cert-manager pod")
		err := f.KubeClientSet.CoreV1().Pods(f.Namespace.Name).Delete(podName, nil)
		Expect(err).NotTo(HaveOccurred())
		err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(secretName, nil)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should generate a signing keypair", func() {
		By("Creating an Issuer")
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().ClusterIssuers().Create(util.NewCertManagerCAClusterIssuer(issuerName, secretName))
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Issuer to become Ready")
		err = util.WaitForClusterIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().ClusterIssuers(),
			issuerName,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})
})
