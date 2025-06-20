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

package certificates

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	e2eutil "github.com/cert-manager/cert-manager/e2e-tests/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/predicate"
	"github.com/cert-manager/cert-manager/test/unit/gen"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// This test ensures that if a Certificates using --cascade=foreground then it
// does not re-create the CertificateRequest and Secret objects
var _ = framework.CertManagerDescribe("Certificate Foreground Deletion", func() {
	const (
		issuerName = "certificate-foreground-deletion"
		secretName = "test-foreground-deletion"
		finalizer  = "e2e.cert-manager.io/foreground-deletion"
	)

	f := framework.NewDefaultFramework("certificates-foreground-deletion")
	ctx := context.Background()

	var crt *cmapi.Certificate

	BeforeEach(func() {
		By("creating a self-signing issuer")
		issuer := gen.Issuer(issuerName+"-self-signed",
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}))
		Expect(f.CRClient.Create(context.Background(), issuer)).To(Succeed())

		By("waiting for self-signing Issuer to become Ready")
		err := e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName+"-self-signed", cmapi.IssuerCondition{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionTrue})
		Expect(err).NotTo(HaveOccurred())

		By("creating a CA Certificate")
		ca := gen.Certificate(issuerName,
			gen.SetCertificateNamespace(f.Namespace.Name),
			gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: issuerName + "-self-signed"}),
			gen.SetCertificateDNSNames("example.com"),
			gen.SetCertificateIsCA(true),
			gen.SetCertificateSecretName("ca-issuer"),
		)
		Expect(f.CRClient.Create(ctx, ca)).To(Succeed())
		_, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, ca, time.Second*10)
		Expect(err).NotTo(HaveOccurred())

		By("creating a CA issuer")
		issuer = gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerCA(cmapi.CAIssuer{SecretName: "ca-issuer"}),
		)
		Expect(f.CRClient.Create(ctx, issuer)).To(Succeed())

		By("waiting for CA Issuer to become Ready")
		err = e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName, cmapi.IssuerCondition{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionTrue})
		Expect(err).NotTo(HaveOccurred())

		crt = &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-foreground-deletion-",
				Namespace:    f.Namespace.Name,
			},
			Spec: cmapi.CertificateSpec{
				CommonName: "test",
				SecretName: secretName,
				PrivateKey: &cmapi.CertificatePrivateKey{RotationPolicy: cmapi.RotationPolicyAlways},
				IssuerRef: cmmeta.ObjectReference{
					Name: issuerName, Kind: "Issuer", Group: "cert-manager.io",
				},
			},
		}

		By("creating a Certificate")
		crt, err = f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Create(ctx, crt, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		crt, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, crt, time.Minute*2)
		Expect(err).NotTo(HaveOccurred(), "failed to wait for Certificate to become Ready")

		By("adding a finalizer to the Certificate")
		Eventually(e2eutil.AddFinalizer).
			WithContext(ctx).
			WithArguments(f.CRClient, crt, finalizer).
			Should(Succeed())

		By("performing a foreground deletion of the Certificate")
		Expect(f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Delete(ctx, crt.Name, metav1.DeleteOptions{PropagationPolicy: ptr.To(metav1.DeletePropagationForeground)})).ToNot(HaveOccurred(), "failed to delete the Certificate")

		// Deleting the secret would normally trigger a new issuance, creating a certificate request
		By("deleting the Certificate secret")
		Expect(f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(ctx, crt.Spec.SecretName, metav1.DeleteOptions{})).ToNot(HaveOccurred(), "failed to delete the Secret")
	})

	AfterEach(func() {
		By("deleting the self-signed issuer")
		err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(context.Background(), issuerName+"-self-signed", metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("deleting the CA issuer")
		err = f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(context.Background(), issuerName, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("removing the finalizer from the Certificate")
		Eventually(e2eutil.RemoveFinalizer).
			WithContext(ctx).
			WithArguments(f.CRClient, crt, finalizer).
			Should(Succeed())
	})

	It("should not create a CertificateRequest while the Certificate is being deleted", func() {
		By("ensuring all CertificateRequest objects are deleted")
		Eventually(e2eutil.ListMatchingPredicates[cmapi.CertificateRequest, cmapi.CertificateRequestList]).
			WithContext(ctx).
			WithArguments(
				f.CRClient,
				predicate.ResourceOwnedBy(crt),
			).
			WithTimeout(time.Second * 10).
			MustPassRepeatedly(10).
			Should(BeEmpty())
	})

	It("should not create a Secret while the Certificate is being deleted", func() {
		By("ensuring all Secret objects are deleted")
		Eventually(e2eutil.ListMatchingPredicates[corev1.Secret, corev1.SecretList]).
			WithContext(ctx).
			WithArguments(
				f.CRClient,
				func(obj runtime.Object) bool {
					secret := obj.(*corev1.Secret)
					return secret.Annotations != nil &&
						secret.Annotations["cert-manager.io/certificate-name"] == crt.Name &&
						secret.Namespace == crt.Namespace
				},
			).
			WithTimeout(time.Second * 10).
			MustPassRepeatedly(10).
			Should(BeEmpty())
	})
})
