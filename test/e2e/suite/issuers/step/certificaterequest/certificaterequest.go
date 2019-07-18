/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package certificaterequest

import (
	"crypto/x509"
	"fmt"
	"net"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	stepaddon "github.com/jetstack/cert-manager/test/e2e/framework/addon/step"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	"github.com/jetstack/cert-manager/test/e2e/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = framework.CertManagerDescribe("Step CertificateRequest", func() {
	f := framework.NewDefaultFramework("create-step-certificate")
	h := f.Helper()

	var (
		tiller = &tiller.Tiller{
			Name:               "tiller-deploy",
			ClusterPermissions: false,
		}
		step = &stepaddon.Step{
			Tiller: tiller,
			Name:   "cm-e2e-create-step-certificate",
		}
	)

	BeforeEach(func() {
		tiller.Namespace = f.Namespace.Name
		step.Namespace = f.Namespace.Name
	})

	f.RequireAddon(tiller)
	f.RequireAddon(step)

	issuerName := "test-step-issuer"
	certificateRequestName := "test-step-certificaterequest"

	exampleDNSNames := []string{"dnsName1.co", "dnsName2.ninja"}
	exampleIPAddresses := []net.IP{
		[]byte{8, 8, 8, 8},
		[]byte{1, 1, 1, 1},
	}
	exampleURIs := []string{"spiffe://foo.foo.example.net", "spiffe://foo.bar.example.net"}

	JustBeforeEach(func() {
		By("Creating an Issuer")
		s := step.Details()
		stepIssuer := util.NewCertManagerStepIssuer(issuerName, s.Host, s.ProvisionerName, s.ProvisionerKeyID, s.ProvisionerPasswordRef, s.ProvisionerPasswordKey, s.CABundle)
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(stepIssuer)
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			stepIssuer.Name,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(issuerName, nil)
	})

	It("should generate a valid certificate from CSR", func() {
		certRequestClient := f.CertManagerClientSet.CertmanagerV1alpha1().CertificateRequests(f.Namespace.Name)

		By("Creating a CertificateRequest")
		cr, key, err := util.NewCertManagerBasicCertificateRequest(certificateRequestName, issuerName, v1alpha1.IssuerKind,
			&metav1.Duration{
				Duration: time.Hour * 24,
			},
			exampleDNSNames, exampleIPAddresses, exampleURIs, x509.ECDSA)
		Expect(err).NotTo(HaveOccurred())
		_, err = certRequestClient.Create(cr)
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the Certificate is valid")
		err = h.WaitCertificateRequestIssuedValidTLS(f.Namespace.Name, certificateRequestName, time.Second*30, key, nil)
		fmt.Println("========>", err)
		time.Sleep(1 * time.Minute)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should be able to obtain a RSA key from an ECDSA backed issuer", func() {
		certRequestClient := f.CertManagerClientSet.CertmanagerV1alpha1().CertificateRequests(f.Namespace.Name)

		By("Creating a CertificateRequest")
		cr, key, err := util.NewCertManagerBasicCertificateRequest(certificateRequestName, issuerName, v1alpha1.IssuerKind,
			&metav1.Duration{
				Duration: time.Hour * 24,
			},
			exampleDNSNames, exampleIPAddresses, exampleURIs, x509.RSA)
		Expect(err).NotTo(HaveOccurred())
		_, err = certRequestClient.Create(cr)
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the Certificate is valid")
		err = h.WaitCertificateRequestIssuedValidTLS(f.Namespace.Name, certificateRequestName, time.Second*30, key, nil)
		Expect(err).NotTo(HaveOccurred())
	})

	cases := []struct {
		inputDuration    *metav1.Duration
		expectedDuration time.Duration
		label            string
	}{
		{
			inputDuration:    nil,
			expectedDuration: time.Hour * 24,
			label:            "the default duration (24 hours)",
		},
		{
			inputDuration:    &metav1.Duration{90 * 24 * time.Hour},
			expectedDuration: 90 * 24 * time.Hour,
			label:            "90 days",
		},
		{
			// extra 30 seconds to avoid bug with duration limits on some
			// step-certificate versions
			inputDuration:    &metav1.Duration{time.Hour + 30*time.Second},
			expectedDuration: time.Hour + 30*time.Second,
			label:            "1 hour",
		},
		{
			inputDuration:    &metav1.Duration{24 * time.Hour},
			expectedDuration: 24 * time.Hour,
			label:            "24 hours",
		},
	}
	for _, v := range cases {
		v := v
		It("should generate a signed certificate valid for "+v.label, func() {
			crClient := f.CertManagerClientSet.CertmanagerV1alpha1().CertificateRequests(f.Namespace.Name)

			By("Creating a CertificateRequest")
			cr, key, err := util.NewCertManagerBasicCertificateRequest(certificateRequestName, issuerName, v1alpha1.IssuerKind, v.inputDuration,
				exampleDNSNames, exampleIPAddresses, exampleURIs, x509.ECDSA)
			Expect(err).NotTo(HaveOccurred())
			cr, err = crClient.Create(cr)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the CertificateRequest is valid")
			err = h.WaitCertificateRequestIssuedValid(f.Namespace.Name, certificateRequestName, time.Second*30, key)
			Expect(err).NotTo(HaveOccurred())
			cr, err = crClient.Get(cr.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			f.CertificateRequestDurationValid(cr, v.expectedDuration)
		})
	}
})
