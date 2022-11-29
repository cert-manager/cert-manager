package certificates

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"time"

	"github.com/cert-manager/cert-manager/internal/webhook/feature"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/test/e2e/framework"
	e2eutil "github.com/cert-manager/cert-manager/test/e2e/util"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	//. "github.com/onsi/gomega/gstruct"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = framework.CertManagerDescribe("literalsubject rdn parsing", func() {

	const (
		testName   = "test-literalsubject-rdn-parsing"
		issuerName = "certificate-literalsubject-rdns"
		secretName = testName
	)

	f := framework.NewDefaultFramework("certificate-literalsubject-rdns")

	createCertificate := func(f *framework.Framework, literalSubject string) (string, *cmapi.Certificate) {
		framework.RequireFeatureGate(f, utilfeature.DefaultFeatureGate, feature.LiteralCertificateSubject)
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

		By("creating Certificate with AdditionalOutputFormats")
		crt, err := f.CertManagerClientSet.CertmanagerV1().Certificates(f.Namespace.Name).Create(context.Background(), crt, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		crt, err = f.Helper().WaitForCertificateReadyAndDoneIssuing(crt, time.Minute*2)
		Expect(err).NotTo(HaveOccurred(), "failed to wait for Certificate to become Ready")

		return crt.Name, crt
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

	FIt("Should create CSR reflecting most common RDNs", func() {
		createCertificate(f, "CN=James \\\"Jim\\\" Smith\\, III,DC=dc,DC=net,UID=jamessmith,STREET=La Rambla,L=Barcelona,C=Spain,O=Acme,OU=IT,OU=Admins")
		secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.TODO(), secretName, metav1.GetOptions{})
		Expect(err).To(BeNil())
		Expect(secret.Data).To(HaveKey("tls.crt"))
		crtPEM := secret.Data["tls.crt"]
		pemBlock, _ := pem.Decode(crtPEM)
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		Expect(err).To(BeNil())

		// TODO: the sequence seems to come out 'reversed' in cert.Subject.Names, investigate ordering
		Expect(cert.Subject.Names).To(Equal([]pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "Admins"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "IT"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Acme"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "Spain"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 7}, Value: "Barcelona"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 9}, Value: "La Rambla"},
			{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: "jamessmith"},
			{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "net"},
			{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "dc"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "James \"Jim\" Smith, III"},
		}))

	})
})
