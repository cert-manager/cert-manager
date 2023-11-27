package certificates

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"math/big"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var (
	testCert           string
	testCertWithoutUrl string
	certBytes          []byte
)

func init() {
	caKey, err := utilpki.GenerateECPrivateKey(256)
	if err != nil {
		panic(err)
	}
	caCertificateTemplate := gen.Certificate(
		"ca",
		gen.SetCertificateCommonName("testing-ca"),
		gen.SetCertificateIsCA(true),
		gen.SetCertificateKeyAlgorithm(certmanagerv1.ECDSAKeyAlgorithm),
		gen.SetCertificateKeySize(256),
		gen.SetCertificateKeyUsages(
			certmanagerv1.UsageDigitalSignature,
			certmanagerv1.UsageKeyEncipherment,
			certmanagerv1.UsageCertSign,
		),
		gen.SetCertificateNotBefore(metav1.Time{Time: time.Now().Add(-time.Hour)}),
		gen.SetCertificateNotAfter(metav1.Time{Time: time.Now().Add(time.Hour)}),
	)
	caCertificateTemplate.Spec.Subject = &certmanagerv1.X509Subject{
		Organizations:       []string{"Internet Widgets, Inc."},
		Countries:           []string{"US"},
		OrganizationalUnits: []string{"WWW"},
		Localities:          []string{"San Francisco"},
		Provinces:           []string{"California"},
	}
	caX509Cert, err := utilpki.GenerateTemplate(caCertificateTemplate)
	if err != nil {
		panic(err)
	}
	_, caCert, err := utilpki.SignCertificate(caX509Cert, caX509Cert, caKey.Public(), caKey)
	if err != nil {
		panic(err)
	}

	testCertKey, err := utilpki.GenerateECPrivateKey(256)
	if err != nil {
		panic(err)
	}
	testCertTemplate := gen.Certificate(
		"testing-cert",
		gen.SetCertificateDNSNames("cert-manager.test"),
		gen.SetCertificateIPs("10.0.0.1"),
		gen.SetCertificateURIs("spiffe://cert-manager.test"),
		gen.SetCertificateEmails("test@cert-manager.io"),
		gen.SetCertificateKeyAlgorithm(certmanagerv1.ECDSAKeyAlgorithm),
		gen.SetCertificateIsCA(false),
		gen.SetCertificateKeySize(256),
		gen.SetCertificateKeyUsages(
			certmanagerv1.UsageDigitalSignature,
			certmanagerv1.UsageKeyEncipherment,
			certmanagerv1.UsageServerAuth,
			certmanagerv1.UsageClientAuth,
		),
		gen.SetCertificateNotBefore(metav1.Time{Time: time.Now().Add(-30 * time.Minute)}),
		gen.SetCertificateNotAfter(metav1.Time{Time: time.Now().Add(30 * time.Minute)}),
	)
	testCertTemplate.Spec.Subject = &certmanagerv1.X509Subject{
		Organizations:       []string{"cncf"},
		Countries:           []string{"GB"},
		OrganizationalUnits: []string{"cert-manager"},
	}
	testX509Cert, err := utilpki.GenerateTemplate(testCertTemplate)
	if err != nil {
		panic(err)
	}

	testCertPEMnoUrl, _, err := utilpki.SignCertificate(testX509Cert, caCert, testCertKey.Public(), caKey)
	if err != nil {
		panic(err)
	}
	testCertWithoutUrl = string(testCertPEMnoUrl)

	testX509Cert.IssuingCertificateURL = []string{"https://test.com/ocsp-endpoint"}
	testX509Cert.OCSPServer = []string{"https://test.com"}
	testCertPEM, _, err := utilpki.SignCertificate(testX509Cert, caCert, testCertKey.Public(), caKey)

	if err != nil {
		panic(err)
	}

	rootPK, err := utilpki.GenerateECPrivateKey(256)
	if err != nil {
		panic(err)
	}
	rootCert, _ := generateSelfSignedCACert(rootPK, "root")
	rootCADER, _ := x509.CreateCertificate(rand.Reader, rootCert, rootCert, rootPK.Public(), rootPK)

	certBytes = rootCADER

	testCert = string(testCertPEM)
}

func generateSelfSignedCACert(key crypto.Signer, name string) (*x509.Certificate, []byte) {
	tmpl := &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(0),
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Minute),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		PublicKey: key.Public(),
		IsCA:      true,
	}

	pem, cert, _ := utilpki.SignCertificate(tmpl, tmpl, key.Public(), key)

	return cert, pem
}

type parseOcsp func(bytes []byte, issuer *x509.Certificate) (*ocsp.Response, error)

func TestOcspManager_GetOCSPResponse(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	tests := map[string]struct {
		cert       *cmapi.Certificate
		req        *cmapi.CertificateRequest
		err        error
		response   httpmock.Responder
		response2  httpmock.Responder
		ocspParser parseOcsp
	}{
		"return empty when issuing certificate URL not present in certificate": {
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
			},
			req: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Certificate: []byte(testCertWithoutUrl),
				},
			},
			err: fmt.Errorf("no issuing certificate URL"),
		},
		"return empty when PEM block in certificate is not present": {
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
			},
			req: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Certificate: []byte(""),
				},
			},
			err: fmt.Errorf("didn't find a PEM block"),
		},
		"return error when cannot connect with the issuer": {
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
			},
			req: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Certificate: []byte(testCert),
				},
			},
			err:      fmt.Errorf("parsing certificate: %w", fmt.Errorf("x509: malformed certificate")),
			response: httpmock.NewStringResponder(503, ""),
		},
		"return result for valid certificate": {
			cert: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "test-namespace", Name: "test-name"},
				Spec: cmapi.CertificateSpec{
					SecretName:     "test-secret",
					SecretTemplate: &cmapi.CertificateSecretTemplate{Annotations: map[string]string{"foo": "bar"}, Labels: map[string]string{"abc": "123"}},
				},
			},
			req: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Certificate: []byte(testCert),
				},
			},
			response:  httpmock.NewStringResponder(200, string(certBytes)),
			response2: httpmock.NewStringResponder(201, ""),
			ocspParser: func(bytes []byte, issuer *x509.Certificate) (*ocsp.Response, error) {
				res := ocsp.Response{
					NextUpdate: time.Now().Add(time.Hour * 144),
					RevokedAt:  time.Now().Add(-time.Hour * 24),
					ThisUpdate: time.Now(),
				}
				return &res, nil
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			httpmock.RegisterResponder("GET", "https://test.com/ocsp-endpoint",
				test.response)
			httpmock.RegisterResponder("POST", "https://test.com", test.response2)

			if test.ocspParser != nil {
				ocspParser = test.ocspParser
			}

			ocspManager := NewOcspManager()
			result, err := ocspManager.GetOCSPResponse(context.Background(), test.cert, test.req)
			if test.err != nil {
				assert.Equal(t, test.err, err)
				assert.Empty(t, result)
			} else {
				assert.NotEmpty(t, result)
			}
		})
	}
}

func TestOcspManager_IsOcspStapleValid(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	tests := map[string]struct {
		cert       []byte
		staple     []byte
		response   httpmock.Responder
		ocspParser parseOcsp
		expected   bool
	}{
		"return true for valid cert and staple": {
			cert:     []byte(testCert),
			staple:   []byte(testCert),
			response: httpmock.NewStringResponder(200, string(certBytes)),
			ocspParser: func(bytes []byte, issuer *x509.Certificate) (*ocsp.Response, error) {
				res := ocsp.Response{
					NextUpdate: time.Now().Add(time.Hour * 144),
					RevokedAt:  time.Now().Add(-time.Hour * 24),
					ThisUpdate: time.Now(),
				}
				return &res, nil
			},
			expected: true,
		},
		"return false for valid cert and staple with incorrect nextUpdate": {
			cert:     []byte(testCert),
			staple:   []byte(testCert),
			response: httpmock.NewStringResponder(200, string(certBytes)),
			ocspParser: func(bytes []byte, issuer *x509.Certificate) (*ocsp.Response, error) {
				res := ocsp.Response{
					NextUpdate: time.Now().Add(time.Hour * 20),
					RevokedAt:  time.Now().Add(-time.Hour * 24),
					ThisUpdate: time.Now(),
				}
				return &res, nil
			},
			expected: false,
		},
		"return false for valid cert and invalid staple": {
			cert:     []byte(testCert),
			staple:   []byte(""),
			response: httpmock.NewStringResponder(200, string(certBytes)),
			ocspParser: func(bytes []byte, issuer *x509.Certificate) (*ocsp.Response, error) {
				res := ocsp.Response{
					NextUpdate: time.Now().Add(time.Hour * 20),
					RevokedAt:  time.Now().Add(-time.Hour * 24),
					ThisUpdate: time.Now(),
				}
				return &res, nil
			},
			expected: false,
		},
		"return false for invalid cert and invalid staple": {
			cert:     []byte(""),
			staple:   []byte(""),
			response: httpmock.NewStringResponder(200, string(certBytes)),
			ocspParser: func(bytes []byte, issuer *x509.Certificate) (*ocsp.Response, error) {
				res := ocsp.Response{
					NextUpdate: time.Now().Add(time.Hour * 20),
					RevokedAt:  time.Now().Add(-time.Hour * 24),
					ThisUpdate: time.Now(),
				}
				return &res, nil
			},
			expected: false,
		},
		"return false for error in api call while getting staple": {
			cert:     []byte(testCert),
			staple:   []byte(""),
			response: httpmock.NewStringResponder(503, ""),
			ocspParser: func(bytes []byte, issuer *x509.Certificate) (*ocsp.Response, error) {
				res := ocsp.Response{
					NextUpdate: time.Now().Add(time.Hour * 20),
					RevokedAt:  time.Now().Add(-time.Hour * 24),
					ThisUpdate: time.Now(),
				}
				return &res, nil
			},
			expected: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			httpmock.RegisterResponder("GET", "https://test.com/ocsp-endpoint", test.response)

			if test.ocspParser != nil {
				ocspParser = test.ocspParser
			}

			ocspManager := NewOcspManager()
			result := ocspManager.IsOcspStapleValid(test.cert, test.staple)
			assert.Equal(t, test.expected, result)
		})
	}
}
