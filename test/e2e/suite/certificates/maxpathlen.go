/*
Copyright 2025 The cert-manager Authors.

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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	e2eutil "github.com/cert-manager/cert-manager/e2e-tests/util"
	internalfeature "github.com/cert-manager/cert-manager/internal/controller/feature"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var _ = framework.CertManagerDescribe("maxPathLen basicConstraint", func() {

	const issuerName = "certificate-maxpathlen"

	f := framework.NewDefaultFramework("certificate-maxpathlen")

	BeforeEach(func(testingCtx context.Context) {
		framework.RequireFeatureGate(utilfeature.DefaultFeatureGate, internalfeature.UseCertificateRequestBasicConstraints)

		By("creating a self-signing issuer")
		issuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}))
		Expect(f.CRClient.Create(testingCtx, issuer)).To(Succeed())

		By("Waiting for Issuer to become Ready")
		err := e2eutil.WaitForIssuerCondition(testingCtx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName, cmapi.IssuerCondition{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionTrue})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func(testingCtx context.Context) {
		Expect(f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(testingCtx, issuerName, metav1.DeleteOptions{})).NotTo(HaveOccurred())
	})

	It("should issue a CA certificate with maxPathLen=2 in BasicConstraints", func(testingCtx context.Context) {
		crt := &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "maxpathlen-",
				Namespace:    f.Namespace.Name,
			},
			Spec: cmapi.CertificateSpec{
				SecretName: "maxpathlen-tls",
				IssuerRef:  cmmeta.IssuerReference{Name: issuerName, Kind: "Issuer", Group: "cert-manager.io"},
				IsCA:       true,
				MaxPathLen: ptr.To(2),
				DNSNames:   []string{e2eutil.RandomSubdomain("example.com")},
			},
		}
		By("creating Certificate with maxPathLen=2")
		crt, err := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Create(testingCtx, crt, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		crt, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testingCtx, crt, time.Minute*2)
		Expect(err).NotTo(HaveOccurred(), "failed to wait for Certificate to become Ready")

		Expect(f.Helper().ValidateCertificate(crt)).NotTo(HaveOccurred())
	})

	It("should issue a CA certificate with maxPathLen=0 (MaxPathLenZero=true) in BasicConstraints", func(testingCtx context.Context) {
		crt := &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "maxpathlen0-",
				Namespace:    f.Namespace.Name,
			},
			Spec: cmapi.CertificateSpec{
				SecretName: "maxpathlen0-tls",
				IssuerRef:  cmmeta.IssuerReference{Name: issuerName, Kind: "Issuer", Group: "cert-manager.io"},
				IsCA:       true,
				MaxPathLen: ptr.To(0),
				DNSNames:   []string{e2eutil.RandomSubdomain("example.com")},
			},
		}
		By("creating Certificate with maxPathLen=0")
		crt, err := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Create(testingCtx, crt, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		crt, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(testingCtx, crt, time.Minute*2)
		Expect(err).NotTo(HaveOccurred(), "failed to wait for Certificate to become Ready")

		Expect(f.Helper().ValidateCertificate(crt)).NotTo(HaveOccurred())
	})
})
