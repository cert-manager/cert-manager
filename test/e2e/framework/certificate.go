package framework

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	testutil "github.com/jetstack/cert-manager/test/util"
)

func (f *Framework) WaitCertificateIssuedValid(c *v1alpha1.Certificate) {
	f.WaitCertificateIssuedValidTimeout(c, longTimeout)
}

// WaitCertificateIssuedValid waits for the given Certificate to be
// 'Ready' and ensures the stored certificate is valid for the specified
// domains.
func (f *Framework) WaitCertificateIssuedValidTimeout(c *v1alpha1.Certificate, t time.Duration) {
	// check the provided certificate is valid
	expectedCN := pki.CommonNameForCertificate(c)
	expectedDNSNames := pki.DNSNamesForCertificate(c)

	By("Waiting for Certificate to become Ready")
	err := testutil.WaitForCertificateCondition(f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(f.Namespace.Name),
		c.Name,
		v1alpha1.CertificateCondition{
			Type:   v1alpha1.CertificateConditionReady,
			Status: v1alpha1.ConditionTrue,
		}, t)
	Expect(err).NotTo(HaveOccurred())
	By("Verifying TLS certificate exists")
	secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(c.Spec.SecretName, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	if len(secret.Data) != 2 {
		Failf("Expected 2 keys in certificate secret, but there was %d", len(secret.Data))
	}
	certBytes, ok := secret.Data[api.TLSCertKey]
	if !ok {
		Failf("No certificate data found for Certificate %q", c.Name)
	}
	cert, err := pki.DecodeX509CertificateBytes(certBytes)
	Expect(err).NotTo(HaveOccurred())
	if expectedCN != cert.Subject.CommonName || !util.EqualUnsorted(cert.DNSNames, expectedDNSNames) {
		Failf("Expected certificate valid for CN %q, dnsNames %v but got a certificate valid for CN %q, dnsNames %v", expectedCN, expectedDNSNames, cert.Subject.CommonName, cert.DNSNames)
	}
}
