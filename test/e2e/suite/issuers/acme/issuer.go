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

package acme

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/e2e-tests/util"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.CertManagerDescribe("ACME Issuer", func() {
	f := framework.NewDefaultFramework("create-acme-issuer")
	ctx := context.TODO()

	issuerName := "test-acme-issuer"

	AfterEach(func() {
		By("Cleaning up")
		err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(context.TODO(), issuerName, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
		err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(context.TODO(), f.Config.Addons.ACMEServer.TestingACMEPrivateKey, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should register ACME account", func() {
		acmeIssuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerACMEEmail(f.Config.Addons.ACMEServer.TestingACMEEmail),
			gen.SetIssuerACMEURL(f.Config.Addons.ACMEServer.URL),
			gen.SetIssuerACMESkipTLSVerify(true),
			gen.SetIssuerACMEPrivKeyRef(f.Config.Addons.ACMEServer.TestingACMEPrivateKey))
		By("Creating an Issuer")
		_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), acmeIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			acmeIssuer.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the ACME account URI is set")
		err = util.WaitForIssuerStatusFunc(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			acmeIssuer.Name,
			func(i *v1.Issuer) (bool, error) {
				if i.GetStatus().ACMEStatus().URI == "" {
					return false, nil
				}
				return true, nil
			})
		Expect(err).NotTo(HaveOccurred())

		By("Verifying ACME account private key exists")
		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.TODO(), f.Config.Addons.ACMEServer.TestingACMEPrivateKey, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		if len(secret.Data) != 1 {
			Fail("Expected 1 key in ACME account private key secret, but there was %d", len(secret.Data))
		}
	})

	It("should recover a lost ACME account URI", func() {
		acmeIssuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerACMEEmail(f.Config.Addons.ACMEServer.TestingACMEEmail),
			gen.SetIssuerACMEURL(f.Config.Addons.ACMEServer.URL),
			gen.SetIssuerACMESkipTLSVerify(true),
			gen.SetIssuerACMEPrivKeyRef(f.Config.Addons.ACMEServer.TestingACMEPrivateKey))
		By("Creating an Issuer")
		_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), acmeIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			acmeIssuer.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the ACME account URI is set")
		var finalURI string
		err = util.WaitForIssuerStatusFunc(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			acmeIssuer.Name,
			func(i *v1.Issuer) (bool, error) {
				if i.GetStatus().ACMEStatus().URI == "" {
					return false, nil
				}
				finalURI = i.GetStatus().ACMEStatus().URI
				return true, nil
			})
		Expect(err).NotTo(HaveOccurred())

		By("Verifying ACME account private key exists")
		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.TODO(), f.Config.Addons.ACMEServer.TestingACMEPrivateKey, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		if len(secret.Data) != 1 {
			Fail("Expected 1 key in ACME account private key secret, but there was %d", len(secret.Data))
		}

		By("Deleting the Issuer")
		err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(context.TODO(), acmeIssuer.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Recreating the Issuer")
		acmeIssuer = gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerACMEEmail(f.Config.Addons.ACMEServer.TestingACMEEmail),
			gen.SetIssuerACMEURL(f.Config.Addons.ACMEServer.URL),
			gen.SetIssuerACMESkipTLSVerify(true),
			gen.SetIssuerACMEPrivKeyRef(f.Config.Addons.ACMEServer.TestingACMEPrivateKey))
		_, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), acmeIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			acmeIssuer.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the ACME account URI has been recovered correctly")
		err = util.WaitForIssuerStatusFunc(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			acmeIssuer.Name,
			func(i *v1.Issuer) (bool, error) {
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
		acmeIssuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerACMEEmail(f.Config.Addons.ACMEServer.TestingACMEEmail),
			gen.SetIssuerACMEURL(f.Config.Addons.ACMEServer.InvalidACMEURL),
			gen.SetIssuerACMESkipTLSVerify(true),
			gen.SetIssuerACMEPrivKeyRef(f.Config.Addons.ACMEServer.TestingACMEPrivateKey))

		By("Creating an Issuer with an invalid server")
		_, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), acmeIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become non-Ready")
		err = util.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			acmeIssuer.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionFalse,
			})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should handle updates to the email field", func() {
		acmeIssuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerACMEEmail(f.Config.Addons.ACMEServer.TestingACMEEmail),
			gen.SetIssuerACMEURL(f.Config.Addons.ACMEServer.URL),
			gen.SetIssuerACMESkipTLSVerify(true),
			gen.SetIssuerACMEPrivKeyRef(f.Config.Addons.ACMEServer.TestingACMEPrivateKey))

		By("Creating an Issuer")
		acmeIssuer, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), acmeIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			acmeIssuer.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the ACME account URI is set")
		err = util.WaitForIssuerStatusFunc(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			acmeIssuer.Name,
			func(i *v1.Issuer) (bool, error) {
				if i.GetStatus().ACMEStatus().URI == "" {
					return false, nil
				}
				return true, nil
			})
		Expect(err).NotTo(HaveOccurred())

		By("Verifying ACME account private key exists")
		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.TODO(), f.Config.Addons.ACMEServer.TestingACMEPrivateKey, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		if len(secret.Data) != 1 {
			Fail("Expected 1 key in ACME account private key secret, but there was %d", len(secret.Data))
		}

		By("Verifying the ACME account email has been registered")
		err = util.WaitForIssuerStatusFunc(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			acmeIssuer.Name,
			func(i *v1.Issuer) (bool, error) {
				registeredEmail := i.GetStatus().ACMEStatus().LastRegisteredEmail
				if registeredEmail == f.Config.Addons.ACMEServer.TestingACMEEmail {
					return true, nil
				}
				return false, nil
			})
		Expect(err).NotTo(HaveOccurred())

		By("Changing the email field")
		acmeIssuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Get(context.TODO(), acmeIssuer.Name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		acmeIssuer.Spec.ACME.Email = f.Config.Addons.ACMEServer.TestingACMEEmailAlternative
		acmeIssuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Update(context.TODO(), acmeIssuer, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for Issuer to become Ready")
		err = util.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			acmeIssuer.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())

		By("Verifying the changed ACME account email has been registered")
		err = util.WaitForIssuerStatusFunc(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			acmeIssuer.Name,
			func(i *v1.Issuer) (bool, error) {
				registeredEmail := i.GetStatus().ACMEStatus().LastRegisteredEmail
				if registeredEmail == f.Config.Addons.ACMEServer.TestingACMEEmailAlternative {
					return true, nil
				}
				return false, nil
			})
		Expect(err).NotTo(HaveOccurred())
	})
	It("ACME account with External Account Binding", func() {

		By("providing the legacy keyAlgorithm value")

		var (
			secretName = "test-secret"
			keyID      = "kid-1"
			key        = "kid-secret-1"
		)

		keyBytes := []byte(base64.RawURLEncoding.EncodeToString([]byte(key)))
		s := gen.Secret(secretName,
			gen.SetSecretNamespace(f.Namespace.Name),
			gen.SetSecretData(map[string][]byte{
				"key": keyBytes,
			}))
		_, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), s, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		acmeIssuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerACMEEmail(f.Config.Addons.ACMEServer.TestingACMEEmail),
			gen.SetIssuerACMEURL(f.Config.Addons.ACMEServer.URL),
			gen.SetIssuerACMESkipTLSVerify(true),
			gen.SetIssuerACMEPrivKeyRef(f.Config.Addons.ACMEServer.TestingACMEPrivateKey),
			gen.SetIssuerACMEEABWithKeyAlgorithm(keyID, secretName, cmacme.HS256))

		acmeIssuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(
			context.TODO(), acmeIssuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		err = util.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			acmeIssuer.Name,
			v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			})
		Expect(err).NotTo(HaveOccurred())

		By("removing the legacy keyAlgorithm value")

		acmeIssuer, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Get(context.TODO(), acmeIssuer.Name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		acmeIssuer = gen.IssuerFrom(acmeIssuer,
			gen.SetIssuerACMEEAB(keyID, secretName))

		_, err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Update(context.TODO(), acmeIssuer, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// TODO: we should use observedGeneration here, but currently it won't
		// be incremented correctly in this scenario.
		// Verify that Issuer's Ready condition remains True for 5 seconds.
		startTime := time.Now()
		successful := false
		err = wait.PollUntilContextCancel(context.TODO(), time.Millisecond*200, true, func(ctx context.Context) (bool, error) {
			// Check if issuer has been ready for 5s
			if time.Since(startTime) > time.Second*5 {
				successful = true
				return true, nil
			}

			iss, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Get(ctx, issuerName, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			if !apiutil.IssuerHasCondition(iss, v1.IssuerCondition{
				Type:   v1.IssuerConditionReady,
				Status: cmmeta.ConditionTrue,
			}) {
				return false, errors.New("expected Ready condition to be true, got false")
			}
			// keep polling
			return false, nil
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(successful).To(BeTrue())
	})
})
