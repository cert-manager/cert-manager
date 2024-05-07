/*
Copyright 2022 The cert-manager Authors.

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

package tpp

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	vaddon "github.com/cert-manager/cert-manager/e2e-tests/framework/addon/venafi"
	"github.com/cert-manager/cert-manager/e2e-tests/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = TPPDescribe("properly configured Venafi TPP Issuer", func() {
	f := framework.NewDefaultFramework("venafi-tpp-setup")
	ctx := context.TODO()

	var (
		issuer   *cmapi.Issuer
		tppAddon = &vaddon.VenafiTPP{}
	)

	BeforeEach(func() {
		tppAddon.Namespace = f.Namespace.Name
	})

	f.RequireAddon(tppAddon)

	AfterEach(func() {
		By("Cleaning up")
		if issuer != nil {
			f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(ctx, issuer.Name, metav1.DeleteOptions{})
		}
	})

	It("should set Ready=True accordingly", func() {
		var err error
		By("Creating a Venafi Issuer resource")
		issuer = tppAddon.Details().BuildIssuer()
		issuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, issuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuer.Name,
			cmapi.IssuerCondition{
				Type:   cmapi.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should set Ready=False with a bad access token", func() {
		var err error
		By("Creating a Venafi Issuer resource")
		issuer = tppAddon.Details().BuildIssuer()
		issuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, issuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		err = util.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuer.Name,
			cmapi.IssuerCondition{
				Type:   cmapi.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())

		By("Changing the Access Token to something bad")
		err = tppAddon.SetAccessToken(ctx, "this_is_a_bad_token")
		Expect(err).NotTo(HaveOccurred())
		err = util.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuer.Name,
			cmapi.IssuerCondition{
				Type:   cmapi.IssuerConditionReady,
				Status: cmmeta.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())
	})
})
