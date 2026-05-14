/*
Copyright 2024 The cert-manager Authors.

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

package ngts

import (
	"context"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	vaddon "github.com/cert-manager/cert-manager/e2e-tests/framework/addon/venafi"
	"github.com/cert-manager/cert-manager/e2e-tests/util"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = NGTSDescribe("properly configured Venafi NGTS Issuer", func() {
	f := framework.NewDefaultFramework("venafi-ngts-setup")

	var (
		issuer    *cmapi.Issuer
		ngtsAddon = &vaddon.VenafiNGTS{}
	)

	BeforeEach(func(testingCtx context.Context) {
		ngtsAddon.Namespace = f.Namespace.Name
	})

	f.RequireAddon(ngtsAddon)

	AfterEach(func(testingCtx context.Context) {
		By("Cleaning up")
		err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(testingCtx, issuer.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should set Ready=True with valid credentials", func(testingCtx context.Context) {
		var err error
		By("Creating a Venafi NGTS Issuer resource")
		issuer = ngtsAddon.Details().BuildIssuer()
		issuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(testingCtx, issuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(testingCtx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuer.Name,
			cmapi.IssuerCondition{
				Type:   cmapi.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should set Ready=False with invalid client credentials", func(testingCtx context.Context) {
		var err error
		By("Creating a Venafi NGTS Issuer resource")
		issuer = ngtsAddon.Details().BuildIssuer()
		issuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(testingCtx, issuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(testingCtx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuer.Name,
			cmapi.IssuerCondition{
				Type:   cmapi.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())

		By("Changing the client credentials to something invalid")
		err = ngtsAddon.SetClientCredentials(testingCtx, "bad-client-id", "bad-client-secret")
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become NotReady")
		err = util.WaitForIssuerCondition(testingCtx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuer.Name,
			cmapi.IssuerCondition{
				Type:   cmapi.IssuerConditionReady,
				Status: cmmeta.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())
	})
})
