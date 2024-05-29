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

package certificates

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	e2eutil "github.com/cert-manager/cert-manager/e2e-tests/util"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/predicate"
	"github.com/cert-manager/cert-manager/test/unit/gen"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// This test ensures that Certificates in the same Namespace who share the same
// `spec.secretName` value are put into a blocking state. This state prevents
// CertificateRequest creation runaway.
var _ = framework.CertManagerDescribe("Certificate Duplicate Secret Name", func() {
	const (
		issuerName = "certificate-duplicate-secret-name"
		secretName = "test-duplicate-secret-name"
	)

	f := framework.NewDefaultFramework("certificates-duplicate-secret-name")
	ctx := context.Background()

	createCertificate := func(f *framework.Framework, pk cmapi.PrivateKeyAlgorithm) string {
		crt := &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-duplicate-secret-name-",
				Namespace:    f.Namespace.Name,
			},
			Spec: cmapi.CertificateSpec{
				CommonName: "test",
				SecretName: secretName,
				PrivateKey: &cmapi.CertificatePrivateKey{
					Algorithm:      pk,
					RotationPolicy: cmapi.RotationPolicyAlways,
				},
				IssuerRef: cmmeta.ObjectReference{
					Name:  issuerName,
					Kind:  "Issuer",
					Group: "cert-manager.io",
				},
			},
		}

		By("creating Certificate")

		crt, err := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Create(ctx, crt, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		return crt.Name
	}

	BeforeEach(func() {
		By("creating a self-signing issuer")
		issuer := gen.Issuer("self-signed",
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}))
		Expect(f.CRClient.Create(ctx, issuer)).To(Succeed())

		By("Waiting for Issuer to become Ready")
		err := e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			"self-signed", cmapi.IssuerCondition{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionTrue})
		Expect(err).NotTo(HaveOccurred())

		// Here we use a CA issuer because if we didn't, we would often get a
		// CertificateRequest failure because private keys do not match on
		// duplicate target Secret names. This failure fails Certificates.
		// This failure is not the point of this test, and the InConflict
		// condition isn't attempting to catch this case.
		By("creating a CA Issuer")
		crt := gen.Certificate(issuerName,
			gen.SetCertificateNamespace(f.Namespace.Name),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "self-signed"}),
			gen.SetCertificateDNSNames("example.com"),
			gen.SetCertificateIsCA(true),
			gen.SetCertificateSecretName("ca-issuer"),
		)
		Expect(f.CRClient.Create(ctx, crt)).To(Succeed())
		_, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, crt, time.Second*10)
		Expect(err).NotTo(HaveOccurred())
		issuer = gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerCA(cmapi.CAIssuer{SecretName: "ca-issuer"}),
		)
		Expect(f.CRClient.Create(ctx, issuer)).To(Succeed())
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName, cmapi.IssuerCondition{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionTrue})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(ctx, issuerName, metav1.DeleteOptions{})).NotTo(HaveOccurred())
	})

	It("if Certificates are created in the same Namsespace with the same spec.secretName, they should block issuance, and never create more than one request.", func() {
		crt1, crt2, crt3 := createCertificate(f, cmapi.ECDSAKeyAlgorithm), createCertificate(f, cmapi.RSAKeyAlgorithm), createCertificate(f, cmapi.ECDSAKeyAlgorithm)

		for _, crtName := range []string{crt1, crt2, crt3} {
			crt, err := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Get(ctx, crtName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Consistently(func() int {
				reqs, err := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).List(ctx, metav1.ListOptions{})
				Expect(err).NotTo(HaveOccurred())
				var ownedReqs int
				for _, req := range reqs.Items {
					if predicate.ResourceOwnedBy(crt)(&req) /* #nosec G601 -- False positive. See https://github.com/golang/go/discussions/56010 */ {
						ownedReqs++
					}
				}
				return ownedReqs
			}, "3s", "500ms").Should(Or(Equal(0), Equal(1)), "expected only zero or single request to be created")
		}

		Consistently(func() bool {
			numberOfReadyCerts := 0

			for _, crtName := range []string{crt1, crt2, crt3} {
				crt, err := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Get(ctx, crtName, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())

				cond := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionReady)
				if cond != nil && cond.Status == cmmeta.ConditionTrue {
					numberOfReadyCerts += 1
				}
			}

			return numberOfReadyCerts <= 1 // only one Certificate should be Ready
		}, "10s", "1s").Should(BeTrue(), "expected at most one Certificate to be Ready")

		By("expect all Certificates to be successfully be issued once all SecretNames are unique")
		for i, crtName := range []string{crt1, crt2, crt3} {
			Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
				crt, err := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Get(ctx, crtName, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				crt.Spec.SecretName = fmt.Sprintf("unique-secret-%d", i)
				_, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Update(ctx, crt, metav1.UpdateOptions{})
				return err
			})).NotTo(HaveOccurred())
		}

		for _, crtName := range []string{crt1, crt2, crt3} {
			crt, err := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Get(ctx, crtName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			_, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, crt, time.Second*10)
			Expect(err).NotTo(HaveOccurred(), "failed to wait for Certificate to become Ready")
		}
	})
})
