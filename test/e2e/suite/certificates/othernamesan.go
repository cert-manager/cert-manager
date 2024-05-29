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

	. "github.com/cert-manager/cert-manager/e2e-tests/framework/matcher"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.CertManagerDescribe("othername san processing", func() {

	const (
		testName   = "test-othername-san-processing"
		issuerName = "certificate-othername-san-processing"
		secretName = testName
	)

	var (
		emailAddresses = []string{"email@domain.test"}
	)

	f := framework.NewDefaultFramework("certificate-othername-san-processing")
	ctx := context.TODO()

	createCertificate := func(f *framework.Framework, OtherNames []cmapi.OtherName) (*cmapi.Certificate, error) {
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
				OtherNames:     OtherNames,
				EmailAddresses: emailAddresses,
				CommonName:     "SOMECN",
			},
		}
		By("creating Certificate with OtherNames")
		return f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Create(ctx, crt, metav1.CreateOptions{})
	}

	BeforeEach(func() {
		framework.RequireFeatureGate(f, utilfeature.DefaultFeatureGate, feature.OtherNames)

		By("creating a self-signing issuer")
		issuer := gen.Issuer(issuerName,
			gen.SetIssuerNamespace(f.Namespace.Name),
			gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}))
		Expect(f.CRClient.Create(ctx, issuer)).To(Succeed())

		By("Waiting for Issuer to become Ready")
		err := e2eutil.WaitForIssuerCondition(ctx, f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name),
			issuerName, cmapi.IssuerCondition{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionTrue})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Delete(ctx, issuerName, metav1.DeleteOptions{})).NotTo(HaveOccurred())
	})

	It("Should create a certificate with the supplied otherName SAN value and emailAddress included", func() {
		crt, err := createCertificate(f, []cmapi.OtherName{
			{
				OID:       "1.3.6.1.4.1.311.20.2.3",
				UTF8Value: "upn@domain.test",
			},
		})
		Expect(err).NotTo(HaveOccurred())
		_, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(ctx, crt, time.Minute*2)
		Expect(err).NotTo(HaveOccurred(), "failed to wait for Certificate to become Ready")

		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.TODO(), secretName, metav1.GetOptions{})
		Expect(err).ToNot(HaveOccurred())
		Expect(secret.Data).To(HaveKey("tls.crt"))
		crtPEM := secret.Data["tls.crt"]
		pemBlock, _ := pem.Decode(crtPEM)
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		Expect(err).ToNot(HaveOccurred())

		By("Including the appropriate GeneralNames ( RFC822 email Address and OtherName) in generated Certificate")

		/* openssl req -nodes -newkey rsa:2048 -subj "/CN=someCN" \
		-addext 'subjectAltName=email:email@domain.test,otherName:msUPN;UTF8:upn@domain.test' -x509 -out server.crt
		*/
		expectedSanExtension := `-----BEGIN CERTIFICATE-----
MIIDRDCCAiygAwIBAgIUdotGup0k8gdZ+irmcuvLeJDm5wkwDQYJKoZIhvcNAQEL
BQAwETEPMA0GA1UEAwwGc29tZUNOMB4XDTIzMTIyMTE2NDQyOFoXDTI0MDEyMDE2
NDQyOFowETEPMA0GA1UEAwwGc29tZUNOMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAyIIWkA1mNi0ZpdwkGeBjmZKZD9J8D9NlpYpOTzoxRLstuJdUNOb0
BgsRk9FWr6rzg6SdSL7NxUS9ZJc0X0P8gn7bPUVtaF7vbj2apz1W2fhx2ifmBRaT
n7ZbpO1aapzr0kiPEZKc82X4jualnFW2YMjjQMc6YuMykcaTQnpv9R4/mzM0kzal
gpKp82tnUogG7EC79cO6xubk0kgIxBFwpH+H6EPLtRY12wW5fONmw9smRgsfleIs
lMSHNuJvUMqyktb8YzAX/XCz3Idumu1UA4ZCFRNCZ019JnmaFF9McGqaC6zrPwnl
aONLw1x9tD+D9bwi6idHNbq/PmQwfs7zzQIDAQABo4GTMIGQMB0GA1UdDgQWBBRm
myeY1slW3mXcGLZs7uciGpfCQzAfBgNVHSMEGDAWgBRmmyeY1slW3mXcGLZs7uci
GpfCQzAPBgNVHRMBAf8EBTADAQH/MD0GA1UdEQQ2MDSBEWVtYWlsQGRvbWFpbi50
ZXN0oB8GCisGAQQBgjcUAgOgEQwPdXBuQGRvbWFpbi50ZXN0MA0GCSqGSIb3DQEB
CwUAA4IBAQCgpAMWkSqA0jV+Bd6UEw7phROTkan5IWTXqYT56RI3AS+LZ83cVglS
FP0UKUssQjLKmubcJWo84T83woxfZVSj15x8X+ohzSvSK8wIe2uobKKNl8F0yW8X
3267YrKGnY6eDqsmNZT8P1isSyYF0PUP3EIDlO6D1YICMawvZItnE+tf9QR+5IIH
3dEzwc2wJsUVYLQ6fgZ4KMfY+fMThY7EDQPsR2M7YFW3p4+3GPQMGBGCOQZysuVh
4uvQbrc9rUWzLMmmJrbb2/xwMm1iCoJfRyLKOGqQV8O6NfnYz5n0/vYzXUCvEbfl
YH0ROM05IRf2nOI6KInaiz4POk6JvdTb
-----END CERTIFICATE-----		
`

		Expect(cert.Extensions).To(HaveSameSANsAs(expectedSanExtension))
	})

	It("Should error if a certificate is supplied with an othername containing an invalid oid value", func() {
		_, err := createCertificate(f, []cmapi.OtherName{
			{
				OID:       "BAD_OID",
				UTF8Value: "userprincipal@domain.com",
			},
			{
				OID:       "1.2.840.113556.1.4.221", // this is the legacy sAMAccountName
				UTF8Value: "user@example.org",
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("admission webhook \"webhook.cert-manager.io\" denied the request: spec.otherNames[0].oid: Invalid value: \"BAD_OID\": oid syntax invalid"))

	})

	It("Should error if a certificate is supplied with an othername without a UTF8 value", func() {
		_, err := createCertificate(f, []cmapi.OtherName{
			{
				OID: "1.3.6.1.4.1.311.20.2.3",
			},
			{
				OID:       "1.2.840.113556.1.4.221", // this is the legacy sAMAccountName
				UTF8Value: "user@example.org",
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("admission webhook \"webhook.cert-manager.io\" denied the request: spec.otherNames[0].utf8Value: Required value: must be set to a valid non-empty UTF8 string"))

	})
})
