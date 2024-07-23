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
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/validation"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/validation/certificates"
	e2eutil "github.com/cert-manager/cert-manager/e2e-tests/util"
	"github.com/cert-manager/cert-manager/internal/controller/feature"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/pkg/util/pki"

	. "github.com/cert-manager/cert-manager/e2e-tests/framework/matcher"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Define defines simple conformance tests that can be run against any issuer type.
// If Complete has not been called on this Suite before Define, it will be
// automatically called.
func (s *Suite) Define() {
	Describe("with issuer type "+s.Name, func() {
		ctx := context.Background()
		f := framework.NewDefaultFramework("certificates")

		sharedIPAddress := "127.0.0.1"

		// Wrap this in a BeforeEach else flags will not have been parsed and
		// f.Config will not be populated at the time that this code is run.
		BeforeEach(func() {
			// Special case Public ACME Servers against being run in the standard
			// e2e tests.
			if strings.Contains(s.Name, "Public ACME Server") && strings.Contains(f.Config.Addons.ACMEServer.URL, "pebble") {
				Skip("Not running public ACME tests against local cluster.")
				return
			}

			if s.HTTP01TestType == "Gateway" {
				framework.RequireFeatureGate(f, utilfeature.DefaultFeatureGate, feature.ExperimentalGatewayAPISupport)
			}

			if s.completed {
				return
			}
			s.complete(f)

			switch s.HTTP01TestType {
			case "Ingress":
				sharedIPAddress = f.Config.Addons.ACMEServer.IngressIP
			case "Gateway":
				sharedIPAddress = f.Config.Addons.ACMEServer.GatewayIP
			}
		})

		s.it(f, "should issue a basic, defaulted certificate for a single distinct DNS Name", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					IssuerRef:  issuerRef,
					DNSNames:   []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.OnlySAN)

		s.it(f, "should issue a CA certificate with the CA basicConstraint set", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					IsCA:       true,
					IssuerRef:  issuerRef,
					DNSNames:   []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.IssueCAFeature)

		s.it(f, "should issue an ECDSA, defaulted certificate for a single distinct DNS Name", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: cmapi.ECDSAKeyAlgorithm,
					},
					DNSNames:  []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
					IssuerRef: issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.ECDSAFeature, featureset.OnlySAN)

		s.it(f, "should issue an Ed25519, defaulted certificate for a single distinct DNS Name", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: cmapi.Ed25519KeyAlgorithm,
					},
					DNSNames:  []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
					IssuerRef: issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.OnlySAN, featureset.Ed25519FeatureSet)

		s.it(f, "should issue a basic, defaulted certificate for a single Common Name", func(issuerRef cmmeta.ObjectReference) {
			// Some issuers use the CN to define the cert's "ID"
			// if one cert manages to be in an error state in the issuer it might throw an error
			// this makes the CN more unique
			cn := "test-common-name-" + rand.String(10)
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					IssuerRef:  issuerRef,
					CommonName: cn,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.CommonNameFeature)

		s.it(f, "should issue a certificate with a couple valid otherName SAN values set as well as an emailAddress", func(issuerRef cmmeta.ObjectReference) {
			framework.RequireFeatureGate(f, utilfeature.DefaultFeatureGate, feature.OtherNames)
			emailAddresses := []string{"email@domain.test"}
			otherNames := []cmapi.OtherName{
				{
					OID:       "1.3.6.1.4.1.311.20.2.3",
					UTF8Value: "upn@domain.test",
				},
				{
					OID:       "1.3.6.1.4.1.311.20.2.3",
					UTF8Value: "upn@domain2.test",
				},
			}

			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName:     "testcert-tls",
					IssuerRef:      issuerRef,
					OtherNames:     otherNames,
					EmailAddresses: emailAddresses,
					CommonName:     "someCN",
				}}

			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")

			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			valFunc := func(certificate *cmapi.Certificate, secret *corev1.Secret) error {
				certBytes, ok := secret.Data[corev1.TLSCertKey]
				if !ok {
					return fmt.Errorf("no certificate data found for Certificate %q (secret %q)", certificate.Name, certificate.Spec.SecretName)
				}

				pemBlock, _ := pem.Decode(certBytes)
				cert, err := x509.ParseCertificate(pemBlock.Bytes)
				Expect(err).ToNot(HaveOccurred())

				By("Including the appropriate GeneralNames ( RFC822 email Address and OtherName) in generated Certificate")
				/* openssl req -nodes -newkey rsa:2048 -subj "/CN=someCN" \
				-addext 'subjectAltName=email:email@domain.test,otherName:msUPN;utf8:upn@domain2.test,otherName:msUPN;UTF8:upn@domain.test' -x509 -out server.crt
				*/
				Expect(cert.Extensions).Should(HaveSameSANsAs(`-----BEGIN CERTIFICATE-----
MIIDZjCCAk6gAwIBAgIUWmJ+z4OCWZg4V3XjSfEN+hItXjUwDQYJKoZIhvcNAQEL
BQAwETEPMA0GA1UEAwwGc29tZUNOMB4XDTI0MDEwMzA4NTU1NloXDTI0MDIwMjA4
NTU1NlowETEPMA0GA1UEAwwGc29tZUNOMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAr5xmoX7/vp+wid+gOvbigYXLP/OvILyRpyj/e6IqJqj83+ImMtHt
QtOHN/E1bYQ8juVXqhhwy5BDXV6qHCfEjAKJF/oHpdVGk4GoMV/noAjbyAdqxFb+
Cr/62sZWFHcuBuh/msJj6MWWAYZkb6HPiyDaV4HdRrrefifQnBGmsO0DE2guy7Yr
CMnE25H0yZ6z1e2tecsXSEkHyPNpil39oJ+1dT3UG8coU32rMOMKs7Za/xF0yMtU
TrCzZ/ylFL4vJi/s0i9zgjBQloJud+s3J+MnbYFgv0MIaosZXuk7/FR0HNIM19Zw
VLH6dgVCcF02bnnVpOAd6KPEzdqjYdDv/QIDAQABo4G1MIGyMB0GA1UdDgQWBBRF
KVGbYoD2H1NE47wJL6xFQ83Q+DAfBgNVHSMEGDAWgBRFKVGbYoD2H1NE47wJL6xF
Q83Q+DAPBgNVHRMBAf8EBTADAQH/MF8GA1UdEQRYMFaBEWVtYWlsQGRvbWFpbi50
ZXN0oCAGCisGAQQBgjcUAgOgEgwQdXBuQGRvbWFpbjIudGVzdKAfBgorBgEEAYI3
FAIDoBEMD3VwbkBkb21haW4udGVzdDANBgkqhkiG9w0BAQsFAAOCAQEAmrouGUth
yyL3jJTe2XZCqbjNgwXrT5N8SwF8JrPNzTyuh4Qiug3N/3djmq4N4V60UAJU8Xpr
Uf8TZBQwF6VD/TSvvJKB3qjSW0T46cF++10ueEgT7mT/icyPeiMw1syWpQlciIvv
WZ/PIvHm2sTB+v8v9rhiFDyQxlnvbtG0D0TV/dEZmyrqfrBpWOP8TFgexRMQU2/4
Gb9fYHRK+LBKRTFudEXNWcDYxK3umfht/ZUsMeWUP70XaNsTd9tQWRsctxGpU10s
cKK5t8N1YDX5CV+01X3vvxpM3ciYuCY9y+lSegrIEI+izRyD7P9KaZlwMaYmsBZq
/XMa5c3nWcbXcA==
-----END CERTIFICATE-----
`))
				return nil
			}

			By("Validating the issued Certificate...")

			err = f.Helper().ValidateCertificate(testCertificate, valFunc)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.OtherNamesFeature)

		s.it(f, "should issue a basic, defaulted certificate for a single distinct DNS Name with a literal subject", func(issuerRef cmmeta.ObjectReference) {
			framework.RequireFeatureGate(f, utilfeature.DefaultFeatureGate, feature.LiteralCertificateSubject)
			// Some issuers use the CN to define the cert's "ID"
			// if one cert manages to be in an error state in the issuer it might throw an error
			// this makes the CN more unique
			host := fmt.Sprintf("*.%s.foo-long.bar.com", rand.String(10))
			literalSubject := fmt.Sprintf("CN=%s,OU=FooLong,OU=Bar,OU=Baz,OU=Dept.,O=Corp.", host)
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName:     "testcert-tls",
					IssuerRef:      issuerRef,
					LiteralSubject: literalSubject,
					DNSNames:       []string{host},
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")

			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*5)
			Expect(err).NotTo(HaveOccurred())

			valFunc := func(certificate *cmapi.Certificate, secret *corev1.Secret) error {
				certBytes, ok := secret.Data[corev1.TLSCertKey]
				if !ok {
					return fmt.Errorf("no certificate data found for Certificate %q (secret %q)", certificate.Name, certificate.Spec.SecretName)
				}

				createdCert, err := pki.DecodeX509CertificateBytes(certBytes)
				if err != nil {
					return err
				}

				var dns pkix.RDNSequence
				rest, err := asn1.Unmarshal(createdCert.RawSubject, &dns)

				if err != nil {
					return err
				}

				rdnSeq, err2 := pki.UnmarshalSubjectStringToRDNSequence(literalSubject)

				if err2 != nil {
					return err2
				}

				fmt.Fprintln(GinkgoWriter, "cert", base64.StdEncoding.EncodeToString(createdCert.RawSubject), dns, err, rest)
				if !reflect.DeepEqual(rdnSeq, dns) {
					return fmt.Errorf("generated certificate's subject [%s] does not match expected subject [%s]", dns.String(), literalSubject)
				}
				return nil
			}

			By("Validating the issued Certificate...")

			err = f.Helper().ValidateCertificate(testCertificate, valFunc)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.LiteralSubjectFeature)

		s.it(f, "should issue an ECDSA, defaulted certificate for a single Common Name", func(issuerRef cmmeta.ObjectReference) {
			// Some issuers use the CN to define the cert's "ID"
			// if one cert manages to be in an error state in the issuer it might throw an error
			// this makes the CN more unique
			cn := "test-common-name-" + rand.String(10)
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: cmapi.ECDSAKeyAlgorithm,
					},
					CommonName: cn,
					IssuerRef:  issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.ECDSAFeature, featureset.CommonNameFeature)

		s.it(f, "should issue an Ed25519, defaulted certificate for a single Common Name", func(issuerRef cmmeta.ObjectReference) {
			// Some issuers use the CN to define the cert's "ID"
			// if one cert manages to be in an error state in the issuer it might throw an error
			// this makes the CN more unique
			cn := "test-common-name-" + rand.String(10)
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: cmapi.Ed25519KeyAlgorithm,
					},
					CommonName: cn,
					IssuerRef:  issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.Ed25519FeatureSet, featureset.CommonNameFeature)

		s.it(f, "should issue a certificate that defines an IP Address", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName:  "testcert-tls",
					IPAddresses: []string{sharedIPAddress},
					IssuerRef:   issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.IPAddressFeature)

		s.it(f, "should issue a certificate that defines a DNS Name and IP Address", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName:  "testcert-tls",
					IPAddresses: []string{sharedIPAddress},
					DNSNames:    []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
					IssuerRef:   issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.OnlySAN, featureset.IPAddressFeature)

		s.it(f, "should issue a certificate that defines a Common Name and IP Address", func(issuerRef cmmeta.ObjectReference) {
			// Some issuers use the CN to define the cert's "ID"
			// if one cert manages to be in an error state in the issuer it might throw an error
			// this makes the CN more unique
			cn := "test-common-name-" + rand.String(10)
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName:  "testcert-tls",
					CommonName:  cn,
					IPAddresses: []string{sharedIPAddress},
					IssuerRef:   issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.CommonNameFeature, featureset.IPAddressFeature)

		s.it(f, "should issue a certificate that defines an Email Address", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName:     "testcert-tls",
					EmailAddresses: []string{"alice@example.com"},
					IssuerRef:      issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.EmailSANsFeature, featureset.OnlySAN)

		s.it(f, "should issue a certificate that defines a Common Name and URI SAN", func(issuerRef cmmeta.ObjectReference) {
			// Some issuers use the CN to define the cert's "ID"
			// if one cert manages to be in an error state in the issuer it might throw an error
			// this makes the CN more unique
			cn := "test-common-name-" + rand.String(10)
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					CommonName: cn,
					URIs:       []string{"spiffe://cluster.local/ns/sandbox/sa/foo"},
					IssuerRef:  issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.URISANsFeature, featureset.CommonNameFeature)

		s.it(f, "should issue a certificate that defines a 2 distinct DNS Names with one copied to the Common Name", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					CommonName: e2eutil.RandomSubdomain(s.DomainSuffix),
					IssuerRef:  issuerRef,
				},
			}
			testCertificate.Spec.DNSNames = []string{
				testCertificate.Spec.CommonName, e2eutil.RandomSubdomain(s.DomainSuffix),
			}

			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.CommonNameFeature)

		s.it(f, "should issue a certificate that defines a distinct DNS Name and another distinct Common Name", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					CommonName: e2eutil.RandomSubdomain(s.DomainSuffix),
					IssuerRef:  issuerRef,
					DNSNames:   []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
				},
			}

			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.CommonNameFeature)

		s.it(f, "should issue a certificate that defines a DNS Name and sets a duration", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					IssuerRef:  issuerRef,
					DNSNames:   []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
					Duration: &metav1.Duration{
						Duration: time.Hour * 896,
					},
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())

			// We set a weird time here as the duration with should never be used as
			// a default by an issuer. This lets us test issuers are using our given
			// duration.
			// We set a 30 second buffer time here since Vault issues certificates
			// with an extra 30 seconds on its duration.
			f.CertificateDurationValid(ctx, testCertificate, time.Hour*896, 30*time.Second)
		}, featureset.DurationFeature, featureset.OnlySAN)

		s.it(f, "should issue a certificate that defines a wildcard DNS Name", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					IssuerRef:  issuerRef,
					DNSNames:   []string{"*." + e2eutil.RandomSubdomain(s.DomainSuffix)},
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.WildcardsFeature, featureset.OnlySAN)

		s.it(f, "should issue a certificate that includes only a URISANs name", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					URIs: []string{
						"spiffe://cluster.local/ns/sandbox/sa/foo",
					},
					IssuerRef: issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.URISANsFeature, featureset.OnlySAN)

		s.it(f, "should issue a certificate that includes arbitrary key usages", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					DNSNames:   []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
					IssuerRef:  issuerRef,
					Usages: []cmapi.KeyUsage{
						cmapi.UsageSigning,
						cmapi.UsageDataEncipherment,
						cmapi.UsageServerAuth,
						cmapi.UsageClientAuth,
					},
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")

			validations := []certificates.ValidationFunc{
				certificates.ExpectKeyUsageExtKeyUsageClientAuth,
				certificates.ExpectKeyUsageExtKeyUsageServerAuth,
				certificates.ExpectKeyUsageUsageDigitalSignature,
				certificates.ExpectKeyUsageUsageDataEncipherment,
			}
			validations = append(validations, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)

			err = f.Helper().ValidateCertificate(testCertificate, validations...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.KeyUsagesFeature, featureset.OnlySAN)

		s.it(f, "should issue another certificate with the same private key if the existing certificate and CertificateRequest are deleted", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					DNSNames:   []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
					IssuerRef:  issuerRef,
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())

			By("Deleting existing certificate data in Secret")
			sec, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).
				Get(ctx, testCertificate.Spec.SecretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to get secret containing signed certificate key pair data")

			sec = sec.DeepCopy()
			crtPEM1 := sec.Data[corev1.TLSCertKey]
			crt1, err := pki.DecodeX509CertificateBytes(crtPEM1)
			Expect(err).NotTo(HaveOccurred(), "failed to get decode first signed certificate data")

			sec.Data[corev1.TLSCertKey] = []byte{}

			_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Update(ctx, sec, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to update secret by deleting the signed certificate data")

			By("Waiting for the Certificate to re-issue a certificate")
			sec, err = f.Helper().WaitForSecretCertificateData(ctx, f.Namespace.Name, sec.Name, time.Minute*8)
			Expect(err).NotTo(HaveOccurred(), "failed to wait for secret to have a valid 2nd certificate")

			crtPEM2 := sec.Data[corev1.TLSCertKey]
			crt2, err := pki.DecodeX509CertificateBytes(crtPEM2)
			Expect(err).NotTo(HaveOccurred(), "failed to get decode second signed certificate data")

			By("Ensuing both certificates are signed by same private key")
			match, err := pki.PublicKeysEqual(crt1.PublicKey, crt2.PublicKey)
			Expect(err).NotTo(HaveOccurred(), "failed to check public keys of both signed certificates")

			if !match {
				Fail("Both signed certificates not signed by same private key")
			}
		}, featureset.ReusePrivateKeyFeature, featureset.OnlySAN)

		s.it(f, "should issue a certificate for a single distinct DNS Name defined by an ingress with annotations", func(issuerRef cmmeta.ObjectReference) {
			if s.HTTP01TestType != "Ingress" {
				// TODO @jakexks: remove this skip once either haproxy or traefik fully support gateway API
				Skip("Skipping ingress-specific as non ingress HTTP-01 solver is in use")
				return
			}
			var certName string
			switch {
			case e2eutil.HasIngresses(f.KubeClientSet.Discovery(), networkingv1.SchemeGroupVersion.String()):
				ingClient := f.KubeClientSet.NetworkingV1().Ingresses(f.Namespace.Name)

				name := "testcert-ingress"
				secretName := "testcert-ingress-tls"

				By("Creating an Ingress with the issuer name annotation set")
				ingress, err := ingClient.Create(ctx, e2eutil.NewIngress(name, secretName, map[string]string{
					"cert-manager.io/issuer":       issuerRef.Name,
					"cert-manager.io/issuer-kind":  issuerRef.Kind,
					"cert-manager.io/issuer-group": issuerRef.Group,
				}, e2eutil.RandomSubdomain(s.DomainSuffix)), metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				certName = ingress.Spec.TLS[0].SecretName
			case e2eutil.HasIngresses(f.KubeClientSet.Discovery(), networkingv1beta1.SchemeGroupVersion.String()):
				ingClient := f.KubeClientSet.NetworkingV1beta1().Ingresses(f.Namespace.Name)
				name := "testcert-ingress"
				secretName := "testcert-ingress-tls"

				By("Creating an Ingress with the issuer name annotation set")
				ingress, err := ingClient.Create(ctx, e2eutil.NewV1Beta1Ingress(name, secretName, map[string]string{
					"cert-manager.io/issuer":       issuerRef.Name,
					"cert-manager.io/issuer-kind":  issuerRef.Kind,
					"cert-manager.io/issuer-group": issuerRef.Group,
				}, e2eutil.RandomSubdomain(s.DomainSuffix)), metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				certName = ingress.Spec.TLS[0].SecretName
			default:
				Fail("Neither " + networkingv1.SchemeGroupVersion.String() + " nor " + networkingv1beta1.SchemeGroupVersion.String() + " were discovered in the API server")
			}

			By("Waiting for the Certificate to exist...")
			cert, err := f.Helper().WaitForCertificateToExist(ctx, f.Namespace.Name, certName, time.Minute)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			cert, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, cert, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(cert, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.OnlySAN)

		s.it(f, "should issue a certificate defined by an ingress with certificate field annotations", func(issuerRef cmmeta.ObjectReference) {
			if s.HTTP01TestType != "Ingress" {
				// TODO @jakexks: remove this skip once either haproxy or traefik fully support gateway API
				Skip("Skipping ingress-specific as non ingress HTTP-01 solver is in use")
				return
			}
			var certName string
			domain := e2eutil.RandomSubdomain(s.DomainSuffix)
			duration := time.Hour * 999
			renewBefore := time.Hour * 111
			revisionHistoryLimit := ptr.To(int32(7))
			privateKeyAlgorithm := cmapi.RSAKeyAlgorithm
			privateKeyEncoding := cmapi.PKCS1
			privateKeySize := 4096
			privateKeyRotationPolicy := cmapi.RotationPolicyAlways

			switch {
			case e2eutil.HasIngresses(f.KubeClientSet.Discovery(), networkingv1.SchemeGroupVersion.String()):
				ingClient := f.KubeClientSet.NetworkingV1().Ingresses(f.Namespace.Name)

				name := "testcert-ingress"
				secretName := "testcert-ingress-tls"

				By("Creating an Ingress with annotations for issuerRef and other Certificate fields")
				ingress, err := ingClient.Create(ctx, e2eutil.NewIngress(name, secretName, map[string]string{
					"cert-manager.io/issuer":                      issuerRef.Name,
					"cert-manager.io/issuer-kind":                 issuerRef.Kind,
					"cert-manager.io/issuer-group":                issuerRef.Group,
					"cert-manager.io/common-name":                 domain,
					"cert-manager.io/duration":                    duration.String(),
					"cert-manager.io/renew-before":                renewBefore.String(),
					"cert-manager.io/revision-history-limit":      strconv.FormatInt(int64(*revisionHistoryLimit), 10),
					"cert-manager.io/private-key-algorithm":       string(privateKeyAlgorithm),
					"cert-manager.io/private-key-encoding":        string(privateKeyEncoding),
					"cert-manager.io/private-key-size":            strconv.Itoa(privateKeySize),
					"cert-manager.io/private-key-rotation-policy": string(privateKeyRotationPolicy),
				}, domain), metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())

				certName = ingress.Spec.TLS[0].SecretName
			case e2eutil.HasIngresses(f.KubeClientSet.Discovery(), networkingv1beta1.SchemeGroupVersion.String()):
				ingClient := f.KubeClientSet.NetworkingV1beta1().Ingresses(f.Namespace.Name)

				name := "testcert-ingress"
				secretName := "testcert-ingress-tls"

				By("Creating an Ingress with annotations for issuerRef and other Certificate fields")
				ingress, err := ingClient.Create(ctx, e2eutil.NewV1Beta1Ingress(name, secretName, map[string]string{
					"cert-manager.io/issuer":                      issuerRef.Name,
					"cert-manager.io/issuer-kind":                 issuerRef.Kind,
					"cert-manager.io/issuer-group":                issuerRef.Group,
					"cert-manager.io/common-name":                 domain,
					"cert-manager.io/duration":                    duration.String(),
					"cert-manager.io/renew-before":                renewBefore.String(),
					"cert-manager.io/revision-history-limit":      strconv.FormatInt(int64(*revisionHistoryLimit), 10),
					"cert-manager.io/private-key-algorithm":       string(privateKeyAlgorithm),
					"cert-manager.io/private-key-encoding":        string(privateKeyEncoding),
					"cert-manager.io/private-key-size":            strconv.Itoa(privateKeySize),
					"cert-manager.io/private-key-rotation-policy": string(privateKeyRotationPolicy),
				}, domain), metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())

				certName = ingress.Spec.TLS[0].SecretName
			default:
				Fail("Neither " + networkingv1.SchemeGroupVersion.String() + " nor " + networkingv1beta1.SchemeGroupVersion.String() + " were discovered in the API server")
			}

			By("Waiting for the Certificate to exist...")
			cert, err := f.Helper().WaitForCertificateToExist(ctx, f.Namespace.Name, certName, time.Minute)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			cert, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, cert, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			// Verify that the ingres-shim has translated all the supplied
			// annotations into equivalent Certificate field values
			By("Validating the created Certificate")
			err = f.Helper().ValidateCertificate(
				cert,
				func(certificate *cmapi.Certificate, _ *corev1.Secret) error {
					Expect(certificate.Spec.DNSNames).To(ConsistOf(domain))
					Expect(certificate.Spec.CommonName).To(Equal(domain))
					Expect(certificate.Spec.Duration.Duration).To(Equal(duration))
					Expect(certificate.Spec.RenewBefore.Duration).To(Equal(renewBefore))
					Expect(certificate.Spec.RevisionHistoryLimit).To(Equal(revisionHistoryLimit))
					Expect(certificate.Spec.PrivateKey.Algorithm).To(Equal(privateKeyAlgorithm))
					Expect(certificate.Spec.PrivateKey.Encoding).To(Equal(privateKeyEncoding))
					Expect(certificate.Spec.PrivateKey.Size).To(Equal(privateKeySize))
					Expect(certificate.Spec.PrivateKey.RotationPolicy).To(Equal(privateKeyRotationPolicy))
					return nil
				},
			)
			Expect(err).NotTo(HaveOccurred())

			// Verify that the issuer has preserved all the Certificate values
			// in the signed certificate
			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(cert, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		})

		s.it(f, "Creating a Gateway with annotations for issuerRef and other Certificate fields", func(issuerRef cmmeta.ObjectReference) {
			framework.RequireFeatureGate(f, utilfeature.DefaultFeatureGate, feature.ExperimentalGatewayAPISupport)

			name := "testcert-gateway"
			secretName := "testcert-gateway-tls"
			domain := e2eutil.RandomSubdomain(s.DomainSuffix)
			duration := time.Hour * 999
			renewBefore := time.Hour * 111

			By("Creating a Gateway with annotations for issuerRef and other Certificate fields")
			gw := e2eutil.NewGateway(name, f.Namespace.Name, secretName, map[string]string{
				"cert-manager.io/issuer":       issuerRef.Name,
				"cert-manager.io/issuer-kind":  issuerRef.Kind,
				"cert-manager.io/issuer-group": issuerRef.Group,
				"cert-manager.io/common-name":  domain,
				"cert-manager.io/duration":     duration.String(),
				"cert-manager.io/renew-before": renewBefore.String(),
			}, domain)

			gw, err := f.GWClientSet.GatewayV1().Gateways(f.Namespace.Name).Create(ctx, gw, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			// XXX(Mael): the CertificateRef seems to contain the Gateway name
			// "testcert-gateway" instead of the secretName
			// "testcert-gateway-tls".
			certName := string(gw.Spec.Listeners[0].TLS.CertificateRefs[0].Name)

			By("Waiting for the Certificate to exist...")
			cert, err := f.Helper().WaitForCertificateToExist(ctx, f.Namespace.Name, certName, time.Minute)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			cert, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, cert, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			// Verify that the gateway-shim has translated all the supplied
			// annotations into equivalent Certificate field values
			By("Validating the created Certificate")
			Expect(cert.Spec.DNSNames).To(ConsistOf(domain))
			Expect(cert.Spec.CommonName).To(Equal(domain))
			Expect(cert.Spec.Duration.Duration).To(Equal(duration))
			Expect(cert.Spec.RenewBefore.Duration).To(Equal(renewBefore))
		})

		s.it(f, "should issue a certificate that defines a long domain", func(issuerRef cmmeta.ObjectReference) {
			// the maximum length of a single segment of the domain being requested
			const maxLengthOfDomainSegment = 63

			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					DNSNames:   []string{e2eutil.RandomSubdomainLength(s.DomainSuffix, maxLengthOfDomainSegment)},
					IssuerRef:  issuerRef,
				},
			}
			validations := validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)

			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Sanity-check the issued Certificate")
			err = f.Helper().ValidateCertificate(testCertificate, validations...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.OnlySAN, featureset.LongDomainFeatureSet)

		s.it(f, "should allow updating an existing certificate with a new DNS Name", func(issuerRef cmmeta.ObjectReference) {
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					DNSNames:   []string{e2eutil.RandomSubdomain(s.DomainSuffix)},
					IssuerRef:  issuerRef,
				},
			}
			validations := validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)

			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate to be ready")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Sanity-check the issued Certificate")
			err = f.Helper().ValidateCertificate(testCertificate, validations...)
			Expect(err).NotTo(HaveOccurred())

			By("Updating the Certificate after having added an additional dnsName")
			newDNSName := e2eutil.RandomSubdomain(s.DomainSuffix)
			retry.RetryOnConflict(retry.DefaultRetry, func() error {
				err = f.CRClient.Get(ctx, types.NamespacedName{Name: testCertificate.Name, Namespace: testCertificate.Namespace}, testCertificate)
				if err != nil {
					return err
				}

				testCertificate.Spec.DNSNames = append(testCertificate.Spec.DNSNames, newDNSName)
				err = f.CRClient.Update(ctx, testCertificate)
				if err != nil {
					return err
				}
				return nil
			})

			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the Certificate Ready condition to be updated")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*8)
			Expect(err).NotTo(HaveOccurred())

			By("Sanity-check the issued Certificate")
			err = f.Helper().ValidateCertificate(testCertificate, validations...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.OnlySAN)

		s.it(f, "should issue a certificate that defines a wildcard DNS Name and its apex DNS Name", func(issuerRef cmmeta.ObjectReference) {
			dnsDomain := e2eutil.RandomSubdomain(s.DomainSuffix)
			testCertificate := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testcert",
					Namespace: f.Namespace.Name,
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testcert-tls",
					IssuerRef:  issuerRef,
					DNSNames:   []string{"*." + dnsDomain, dnsDomain},
				},
			}
			By("Creating a Certificate")
			err := f.CRClient.Create(ctx, testCertificate)
			Expect(err).NotTo(HaveOccurred())

			// use a longer timeout for this, as it requires performing 2 dns validations in serial
			By("Waiting for the Certificate to be issued...")
			testCertificate, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, testCertificate, time.Minute*10)
			Expect(err).NotTo(HaveOccurred())

			By("Validating the issued Certificate...")
			err = f.Helper().ValidateCertificate(testCertificate, validation.CertificateSetForUnsupportedFeatureSet(s.UnsupportedFeatures)...)
			Expect(err).NotTo(HaveOccurred())
		}, featureset.WildcardsFeature, featureset.OnlySAN)
	})
}
