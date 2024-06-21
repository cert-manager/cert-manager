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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	e2eutil "github.com/cert-manager/cert-manager/e2e-tests/util"
	"github.com/cert-manager/cert-manager/internal/webhook/feature"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/test/unit/gen"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.CertManagerDescribe("literalsubject rdn parsing", func() {
	const (
		testName   = "test-literalsubject-rdn-parsing"
		issuerName = "certificate-literalsubject-rdns"
		secretName = testName
	)

	ctx := context.TODO()
	f := framework.NewDefaultFramework("certificate-literalsubject-rdns")

	createCertificate := func(f *framework.Framework, literalSubject string) (*cmapi.Certificate, error) {
		framework.RequireFeatureGate(utilfeature.DefaultFeatureGate, feature.LiteralCertificateSubject)
		crt := &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: testName + "-",
				Namespace:    f.Namespace.Name,
			},
			Spec: cmapi.CertificateSpec{
				SecretName: secretName,
				PrivateKey: &cmapi.CertificatePrivateKey{RotationPolicy: cmapi.RotationPolicyAlways},
				IssuerRef: cmmeta.ObjectReference{
					Name: issuerName, Kind: "Issuer", Group: "cert-manager.io",
				},
				LiteralSubject: literalSubject,
			},
		}

		By("creating Certificate with LiteralSubject")
		return f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Create(context.Background(), crt, metav1.CreateOptions{})

	}

	BeforeEach(func() {
		By("creating a self-signing issuer")
		issuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}))
		Expect(f.CRClient.Create(context.Background(), issuer)).To(Succeed())

		By("Waiting for Issuer to become Ready")
		err := e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName, cmapi.IssuerCondition{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionTrue})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(context.Background(), issuerName, metav1.DeleteOptions{})).NotTo(HaveOccurred())
	})

	// The parsed RDNSequence should be in REVERSE order as RDNs in String format are expected to be written in reverse order.
	// Meaning, a string of "CN=Foo,OU=Bar,O=Baz" actually should have "O=Baz" as the first element in the RDNSequence.
	It("Should create a certificate with all the supplied RDNs as subject names in reverse string order, including DC and UID", func() {
		crt, err := createCertificate(f, "CN=James \\\"Jim\\\" Smith\\, III,UID=jamessmith,SERIALNUMBER=1234512345,OU=Admins,OU=IT,DC=net,DC=dc,O=Acme,STREET=La Rambla,L=Barcelona,C=Spain")
		Expect(err).NotTo(HaveOccurred())
		_, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, crt, time.Minute*2)
		Expect(err).NotTo(HaveOccurred(), "failed to wait for Certificate to become Ready")

		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.TODO(), secretName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(secret.Data).To(HaveKey("tls.crt"))
		crtPEM := secret.Data["tls.crt"]
		pemBlock, _ := pem.Decode(crtPEM)
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())

		Expect(cert.Subject.Names).To(Equal([]pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "Spain"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 7}, Value: "Barcelona"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 9}, Value: "La Rambla"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Acme"},
			{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "dc"},
			{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "net"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "IT"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "Admins"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 5}, Value: "1234512345"},
			{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: "jamessmith"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "James \"Jim\" Smith, III"},
		}))
	})

	It("Should not allow unknown RDN component", func() {
		_, err := createCertificate(f, "UNKNOWN=blah")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Literal subject contains unrecognized key with value [blah]"))
	})

})
