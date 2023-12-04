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
	"fmt"
	"time"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	e2eutil "github.com/cert-manager/cert-manager/e2e-tests/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = framework.CertManagerDescribe("othername san processing", func() {

	const (
		testName      = "test-othername-san-processing"
		issuerName    = "certificate-othername-san-processing"
		secretName    = testName
		nameTypeEmail = 1
	)

	var (
		oidExtensionSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
		otherNameParam             = fmt.Sprintf("tag:0")
		emailAddresses             = []string{"email@domain.com"}
	)
	// StringValueLikeType type for asn1 encoding. This will hold
	// our utf-8 encoded string.
	type StringValueLikeType struct {
		A string `asn1:"utf8"`
	}

	type OtherName struct {
		OID   asn1.ObjectIdentifier
		Value StringValueLikeType `asn1:"tag:0"`
	}

	f := framework.NewDefaultFramework("certificate-othername-san-processing")
	createCertificate := func(f *framework.Framework, OtherNameSANs []cmapi.OtherNameSAN) (*cmapi.Certificate, error) {
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
				OtherNameSANs:  OtherNameSANs,
				EmailAddresses: emailAddresses,
			},
		}
		By("creating Certificate with OtherNameSANs")
		return f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Create(context.Background(), crt, metav1.CreateOptions{})
	}

	BeforeEach(func() {
		By("creating a self-signing issuer")
		issuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}))
		Expect(f.CRClient.Create(context.Background(), issuer)).To(Succeed())

		By("Waiting for Issuer to become Ready")
		err := e2eutil.WaitForIssuerCondition(f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName, cmapi.IssuerCondition{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionTrue})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(context.Background(), issuerName, metav1.DeleteOptions{})).NotTo(HaveOccurred())
	})

	It("Should create a certificate with the supplied otherName SAN values and emailAddresses included", func() {
		crt, err := createCertificate(f, []cmapi.OtherNameSAN{
			{
				OID:         "1.3.6.1.4.1.311.20.2.3",
				StringValue: "userprincipal@domain.com",
			},
			{
				OID:         "1.2.840.113556.1.4.221", // this is the legacy sAMAccountName but could be any oid
				StringValue: "user@example.org",
			},
		})
		Expect(err).NotTo(HaveOccurred())
		_, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(crt, time.Minute*2)
		Expect(err).NotTo(HaveOccurred(), "failed to wait for Certificate to become Ready")

		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.TODO(), secretName, metav1.GetOptions{})
		Expect(err).To(BeNil())
		Expect(secret.Data).To(HaveKey("tls.crt"))
		crtPEM := secret.Data["tls.crt"]
		pemBlock, _ := pem.Decode(crtPEM)
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		Expect(err).To(BeNil())

		By("Including the supplied RFC822 email Address")
		Expect(cert.EmailAddresses).To(Equal(emailAddresses))

		By("Including the supplied otherName values in SAN Extension")

		OtherNameSANRawVal := func(expectedOID asn1.ObjectIdentifier, value string) asn1.RawValue {
			otherNameDer, err := asn1.MarshalWithParams(OtherName{
				OID: expectedOID, // UPN OID
				Value: StringValueLikeType{
					A: value,
				}}, otherNameParam)

			Expect(err).To(BeNil())
			rawVal := asn1.RawValue{
				FullBytes: otherNameDer,
			}
			return rawVal
		}

		asn1otherNameUpnSANRawVal := OtherNameSANRawVal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}, "userprincipal@domain.com") // UPN OID
		asn1otherNamesAMAAccountNameRawVal := OtherNameSANRawVal(asn1.ObjectIdentifier{1, 2, 840, 113556, 1, 4, 221}, "user@example.org")   // sAMAccountName OID

		MustMarshalSAN := func(generalNames []asn1.RawValue) pkix.Extension {
			val, err := asn1.Marshal(generalNames)
			Expect(err).To(BeNil())
			return pkix.Extension{
				Id:    oidExtensionSubjectAltName,
				Value: val,
			}
		}
		expectedSanExtension := MustMarshalSAN([]asn1.RawValue{
			asn1otherNameUpnSANRawVal,
			asn1otherNamesAMAAccountNameRawVal,
			{Tag: nameTypeEmail, Class: 2, Bytes: []byte("email@domain.com")},
		})
		Expect(cert.Extensions).To(ContainElement(expectedSanExtension))
	})
})
