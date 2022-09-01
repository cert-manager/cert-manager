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

package ca

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/e2e/framework"
	"github.com/cert-manager/cert-manager/test/e2e/util"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = framework.CertManagerDescribe("CA Issuer", func() {
	f := framework.NewDefaultFramework("create-ca-issuer")

	issuerName := "test-ca-issuer"
	secretName := "ca-issuer-signing-keypair"

	BeforeEach(func() {
		By("Creating a signing keypair fixture")
		_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), newSigningKeypairSecret(secretName), metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Cleaning up")
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(context.TODO(), secretName, metav1.DeleteOptions{})
	})

	It("should generate a signing keypair", func() {
		By("Creating an Issuer")
		issuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerCASecretName(secretName))
		_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), issuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})
})
