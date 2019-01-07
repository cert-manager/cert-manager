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

package acme

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/pebble"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	"github.com/jetstack/cert-manager/test/e2e/util"
)

const invalidACMEURL = "http://not-a-real-acme-url.com"
const testingACMEEmail = "test@example.com"
const testingACMEPrivateKey = "test-acme-private-key"

var _ = framework.CertManagerDescribe("ACME Issuer", func() {
	f := framework.NewDefaultFramework("create-acme-issuer")

	var (
		tiller = &tiller.Tiller{
			Name:               "tiller-deploy",
			ClusterPermissions: false,
		}
		pebble = &pebble.Pebble{
			Tiller: tiller,
			Name:   "cm-e2e-create-acme-issuer",
		}
	)

	BeforeEach(func() {
		tiller.Namespace = f.Namespace.Name
		pebble.Namespace = f.Namespace.Name
	})

	f.RequireGlobalAddon(addon.NginxIngress)
	f.RequireAddon(tiller)
	f.RequireAddon(pebble)

	issuerName := "test-acme-issuer"

	AfterEach(func() {
		By("Cleaning up")
		f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(issuerName, nil)
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(testingACMEPrivateKey, nil)
	})

	It("should register ACME account", func() {
		acmeURL := pebble.Details().Host
		acmeIssuer := util.NewCertManagerACMEIssuer(issuerName, acmeURL, testingACMEEmail, testingACMEPrivateKey)

		By("Creating an Issuer")
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(acmeIssuer)
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			acmeIssuer.Name,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the ACME account URI is set")
		err = util.WaitForIssuerStatusFunc(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			acmeIssuer.Name,
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

	It("should recover a lost ACME account URI", func() {
		acmeURL := pebble.Details().Host
		acmeIssuer := util.NewCertManagerACMEIssuer(issuerName, acmeURL, testingACMEEmail, testingACMEPrivateKey)

		By("Creating an Issuer")
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(acmeIssuer)
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			acmeIssuer.Name,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the ACME account URI is set")
		var finalURI string
		err = util.WaitForIssuerStatusFunc(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			acmeIssuer.Name,
			func(i *v1alpha1.Issuer) (bool, error) {
				if i.GetStatus().ACMEStatus().URI == "" {
					return false, nil
				}
				finalURI = i.GetStatus().ACMEStatus().URI
				return true, nil
			})
		Expect(err).NotTo(HaveOccurred())

		By("Verifying ACME account private key exists")
		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(testingACMEPrivateKey, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		if len(secret.Data) != 1 {
			Fail("Expected 1 key in ACME account private key secret, but there was %d", len(secret.Data))
		}

		By("Deleting the Issuer")
		err = f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Delete(acmeIssuer.Name, &metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Recreating the Issuer")
		acmeIssuer = util.NewCertManagerACMEIssuer(issuerName, acmeURL, testingACMEEmail, testingACMEPrivateKey)
		_, err = f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(acmeIssuer)
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			acmeIssuer.Name,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the ACME account URI has been recovered correctly")
		err = util.WaitForIssuerStatusFunc(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			acmeIssuer.Name,
			func(i *v1alpha1.Issuer) (bool, error) {
				uri := i.GetStatus().ACMEStatus().URI
				if uri == "" {
					return false, nil
				}
				if uri != finalURI {
					return false, fmt.Errorf("expected account URI to equal %q, but was %q", finalURI, uri)
				}
				return true, nil
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should fail to register an ACME account", func() {
		acmeIssuer := util.NewCertManagerACMEIssuer(issuerName, invalidACMEURL, testingACMEEmail, testingACMEPrivateKey)

		By("Creating an Issuer with an invalid server")
		_, err := f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name).Create(acmeIssuer)
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become non-Ready")
		err = util.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(f.Namespace.Name),
			acmeIssuer.Name,
			v1alpha1.IssuerCondition{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())
	})
})
