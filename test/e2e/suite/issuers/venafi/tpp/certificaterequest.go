/*
Copyright 2018 The Jetstack cert-manager contributors.

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
	"crypto/x509"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmutil "github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	vaddon "github.com/jetstack/cert-manager/test/e2e/suite/issuers/venafi/addon"
	"github.com/jetstack/cert-manager/test/e2e/util"
)

var _ = TPPDescribe("CertificateRequest with a properly configured Issuer", func() {
	f := framework.NewDefaultFramework("venafi-tpp-certificaterequest")
	h := f.Helper()

	var (
		issuer                 *cmapi.Issuer
		tppAddon               = &vaddon.VenafiTPP{}
		certificateRequestName = "test-venafi-certificaterequest"
	)

	BeforeEach(func() {
		tppAddon.Namespace = f.Namespace.Name
	})

	f.RequireAddon(tppAddon)

	// Create the Issuer resource
	BeforeEach(func() {
		var err error

		By("Creating a Venafi Issuer resource")
		issuer = tppAddon.Details().BuildIssuer()
		issuer, err = f.CertManagerClientSet.CertmanagerV1alpha2().Issuers(f.Namespace.Name).Create(issuer)
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha2().Issuers(f.Namespace.Name),
			issuer.Name,
			cmapi.IssuerCondition{
				Type:   cmapi.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1alpha2().Issuers(f.Namespace.Name).Delete(issuer.Name, nil)
	})

	It("should obtain a signed certificate for a single domain", func() {
		crClient := f.CertManagerClientSet.CertmanagerV1alpha2().CertificateRequests(f.Namespace.Name)

		dnsNames := []string{cmutil.RandStringRunes(10) + ".venafi-e2e.example"}

		cr, key, err := util.NewCertManagerBasicCertificateRequest(certificateRequestName, issuer.Name, cmapi.IssuerKind, nil, dnsNames, nil, nil, x509.RSA)
		Expect(err).NotTo(HaveOccurred())

		By("Creating a CertificateRequest")
		_, err = crClient.Create(cr)
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the CertificateRequest is valid")
		err = h.WaitCertificateRequestIssuedValid(f.Namespace.Name, certificateRequestName, time.Second*30, key)
		Expect(err).NotTo(HaveOccurred())
	})
})
