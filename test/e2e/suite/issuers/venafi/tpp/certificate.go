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

package tpp

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmutil "github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	vaddon "github.com/jetstack/cert-manager/test/e2e/suite/issuers/venafi/addon"
	"github.com/jetstack/cert-manager/test/e2e/util"
)

var _ = TPPDescribe("Certificate with a properly configured Issuer", func() {
	f := framework.NewDefaultFramework("venafi-tpp-certificate")

	var (
		issuer                *cmapi.Issuer
		tppAddon              = &vaddon.VenafiTPP{}
		certificateName       = "test-venafi-cert"
		certificateSecretName = "test-venafi-cert-tls"
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
		issuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), issuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuer.Name,
			cmapi.IssuerCondition{
				Type:   cmapi.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(context.TODO(), issuer.Name, metav1.DeleteOptions{})
	})

	It("should obtain a signed certificate for a single domain", func() {
		certClient := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name)

		crt := util.NewCertManagerBasicCertificate(certificateName, certificateSecretName, issuer.Name, cmapi.IssuerKind, nil, nil)
		crt.Spec.CommonName = cmutil.RandStringRunes(10) + ".venafi-e2e.example"

		By("Creating a Certificate")
		_, err := certClient.Create(context.TODO(), crt, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for the Certificate to be issued...")
		err = f.Helper().WaitForCertificateReady(f.Namespace.Name, certificateName, time.Minute*5)
		Expect(err).NotTo(HaveOccurred())

		By("Validating the issued Certificate...")
		err = f.Helper().ValidateCertificate(f.Namespace.Name, certificateName)
		Expect(err).NotTo(HaveOccurred())
	})
})
