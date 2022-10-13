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

package vault

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	corev1 "k8s.io/api/core/v1"
	clientcorev1 "k8s.io/client-go/listers/core/v1"

	vaultfake "github.com/cert-manager/cert-manager/internal/vault/fake"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	"github.com/cert-manager/cert-manager/test/unit/listers"
)

const (
	testLeafCertificate = `-----BEGIN CERTIFICATE-----
MIIFFTCCAv2gAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwRjELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAkNBMRQwEgYDVQQKDAtDRVJUTUFOQUdFUjEUMBIGA1UEAwwLZm9v
LmJhci5pbnQwHhcNMjAxMDAyMTQ1NzMwWhcNMjExMDEyMTQ1NzMwWjBKMQswCQYD
VQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAoMC0NFUlRNQU5BR0VSMRgwFgYD
VQQDDA9leGFtcGxlLmZvby5iYXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC8yTGzYIX3OoRma11vewbNf8dgKHc9GgvJJ29SVjaNwRAJjKOXokGOwcyQ
7Ieb1puYQ5KdSPC1IxyUx77URovIvd3Wql+J1gIxyrdN3om3uQdJ2ck6xatBZ8BI
Y3Z+6WpUQ2067Wk4KpUGfMrbGg5zVcesh6zc8J9yEiItUENeR+6GyEf+B8IJ0xqe
5lps2LaxZp6I6vaKeMELjj17Nb9r81Rjyk8BN7yX74tFE1mUGX9o75tsODU9IrYW
nqSl5gr2PO9Zb/bd6zhoncLJr9kj2tk6cLRPht+JOPoA2LAP6D0aEdC3a2XWuj2E
EsUYJR9e5C/X49VQaak0VdNnhO6RAgMBAAGjggEHMIIBAzAJBgNVHRMEAjAAMBEG
CWCGSAGG+EIBAQQEAwIGQDAzBglghkgBhvhCAQ0EJhYkT3BlblNTTCBHZW5lcmF0
ZWQgU2VydmVyIENlcnRpZmljYXRlMB0GA1UdDgQWBBQ41U/GiA2rQtuMz6tNL55C
o4pnBDBqBgNVHSMEYzBhgBSfus9cb7UA/PCfHJAGtL6ot2EpLKFFpEMwQTEPMA0G
A1UEAwwGYmFyLmNhMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAoM
C0NFUlRNQU5BR0VSggIQADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwDQYJKoZIhvcNAQELBQADggIBAFFTJNqKSkkJNWWt+R7WFNIEKoaPcFH5
yupCQRYX9LK2cXdBQpF458/PFxREyt5jKFUcDyzQhOglFYq0hfcoAc2EB3Vw8Ww9
c4QCiCU6ehJVMRt7MzZ9uUVGCRVOA+Fa1tIFfL3dKlI+4pTSbDhNHRqDtFhfWOZK
bgtruQEUOW1lQR61AsidOF1iwDBU6ckpVY9Lc2SHEAfQFs0MoXmJ8B4MqFptF4+H
al+IAeQ1bC/2EccFYg3tq9+YKHDCyghHf8qeKJR9tZslvkHrAzuX56e0MHxM3AD6
D0L8nG3DsrHcjK0MlVUWmq0QFnY5t+78iocLoQZzpILZYuZn3p+XNlUdW4lcqSBn
y5fUwQ3RIuvN66GBhTeDV4vzYPa7g3i9PoBFoG50Ayr6VtIVn08rnl03lgp57Edv
A5oRrSHcd8Hd8/lk0Y9BpFTnZEg7RLhFhh9nazVp1/pjwaGx449uHIGEoxREQoPq
9Q+KLGMJR2IqiNI6+U1z2j8BChTOPkuAvsnSuAXyotu4BXBL5zbDzfDoggEk1ps1
bfHWnmdelE0WP7h7B0PSA0EXn0pdg2VQIQsknV6y3MCzFQCCSAog/OSguokXG1PG
l6fctDJ3+AF07EjtgArOBkUn7Nt3/CgMN8I1rnBZ1Vmd8yrHEP0E3yRXBL7cDj5j
Fqmd89NQLlGs
-----END CERTIFICATE-----
`

	testIntermediateCa = `-----BEGIN CERTIFICATE-----
MIIFaTCCA1GgAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwQTEPMA0GA1UEAwwGYmFy
LmNhMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAoMC0NFUlRNQU5B
R0VSMB4XDTIwMTAwMjE0NTY1MFoXDTMwMDkzMDE0NTY1MFowRjELMAkGA1UEBhMC
VVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQKDAtDRVJUTUFOQUdFUjEUMBIGA1UEAwwL
Zm9vLmJhci5pbnQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCv1hQq
Gg5LN0zekkaOzu/Xk2PUDA3ysEOXfzjL1EQ5guno93sH5WCG0tUbGQbzQyCXuyG+
bbeGiUXhF3vPPH5yAHNoLz14GQ9WRe3Y93Lco0qD3jcgw90ctrEcOsq69Eqr6PB/
fV3P5fKmqZcy3kywaM+suvZ3AvMVMHXKODpPSo9f8uuXd5VYvjqUUllA+iGJNUu8
hfThn+pUMDbdAEXckIfDHqZlDQxRmRsySi0kHB1Tjgo3eH/Mj+00ZSbxEhxj2HFs
0Vn81Uo0lVjvQ6oPIm19KIo2/nOZowuy94idXSWkdXCv1UjVSVRo2NHWlH3meKWs
pALeV8Z68shyVC8HjHBAbElumBTLiWQfpQYOa0MNaBRBvp3x8ajDcx5RfqG7n45i
Ezd/UrC0mcnC0dzhFySEjPgkqZ35vEcxoDDfUJ/aLt7laBL4MPZ2U2BddQjfJVQA
A0mP1l7MPBk3+qrwErci8D+iYT4I4sQs31ip/Ht5sfc9zsF9wVlOgMx44LN0AWrE
FK+ufWeB8npJAwkfwoyfwlyvJGwwhP7PMR57y24nQvife29FnqjYdA43QQzhgXO5
iktI0B9ApVw12/cxfMFC64fcUZF8ENpCMIM0IpoYMeFNyvod4UV0OZY06zUGindh
4qwh8U3qxQ4+bTTF9hkuiKq+9nd52GRt7BSpxwIDAQABo2YwZDAdBgNVHQ4EFgQU
n7rPXG+1APzwnxyQBrS+qLdhKSwwHwYDVR0jBBgwFoAUl2WJOv19aAspu+JphX7I
PkCr2ogwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZI
hvcNAQELBQADggIBAGLWfRG5rHuf+t+ebU+XJj0QFUWxt08glVwJLvR7EBTxMtfa
D4Da3OYCyY78SIqWHpa51UC727GRUxKZxFrNtyPBQaBmLF4lm0xRoM1EZTqtF+Qf
yJTd92YQQJNYUCZS8NvCt2+9h9d7Gb11wOc/r5IqQ9boRP2VW7UjqmqZeBeo+Dfw
5VBg8ytF+XvrEJtp2nEobbGK2ZXPkOBt1aUVz57e3BpDw6bRbWnz8fbiEsN2b7Zs
Z5JtP8NaX81ZMV8MYeX2GRH5z8xeXjdb5xyVZHlv8mWrlN7uaRhK4AlWJ9Cdcq+x
Z5rhvg7nTfd4GoTuAhGIgW8qBNGdn6DVGURu33+w1roZn4J1tfD+Se2Oo5TScM+F
068TweDlwfYP0p+2YMKmUvQxB5R74x0Y2+49btpXXHSd/euT1PVHtc84g3acTwfK
rFQvv3jOPJ99IUpYpJydpv0Rfds3zMy2FJ6uex8gmlF7+XDZUSLQLuuFcjyHybfB
zwZlUQ6EVmjOWLDdAmpeIAIkNEiogPuSz9E7xKdU+5bFYSgm6uxe8tFZSge2VEMC
vPY2RcZ6uPZwpItqPmna8beydzlYohPcNcs4eK3hblLLacBV6eltP+q4/td+y87N
yNCb90/k5dhi3YML4qoFeZjYfbY65RKHTztv5iqHH36dIZos0LucuphEWlKK
-----END CERTIFICATE-----
`
	testRootCa = `-----BEGIN CERTIFICATE-----
MIIFczCCA1ugAwIBAgIUcq3TKhc/RJfQOLCF2UQ805R+lkIwDQYJKoZIhvcNAQEL
BQAwQTEPMA0GA1UEAwwGYmFyLmNhMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0Ex
FDASBgNVBAoMC0NFUlRNQU5BR0VSMB4XDTIwMTAwMjE0NTY0MVoXDTQwMDkyNzE0
NTY0MVowQTEPMA0GA1UEAwwGYmFyLmNhMQswCQYDVQQGEwJVUzELMAkGA1UECAwC
Q0ExFDASBgNVBAoMC0NFUlRNQU5BR0VSMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
MIICCgKCAgEAmEzgpmKns5FOmfjmOm6WBcdAZ8N0oXpVmx3atfsTeedavgi71AyL
NTwL1cwi3Y6UANMvSk0tca4YAZ2phVSvgaUmNXWXNbrrS/K5R73XpDos3igHTTvP
0kuVXgYSY2iXELA+UmzQFMpjCwBOeriz3oFA0JZxQaX4h7vZqSsabOArywTihwNt
SMH8a3ErdKwkYx9DNZYIwsU8+YIViJgx55Covenj/qoJ3ULsm5B3ILlvN4KDcVeQ
UPKPa5B5MeMS5XNoX1wNzwpLGV+9QVFQScxLAm9rcksWLm3xoUkPvNZkT3891VPo
MHT5kXFmM/7ynTC/fvG5Z4vxWm105d2WwYOJqmJR7q8/TmsNzL8+J8SojqWL1xYQ
wds4/5XYgdXBMVaaFAOYDOczIU7v3hu6Zn4UGJWSlgNiC1+xBRY0iYQSnNrhtwev
w+oO8qvXZYN05/g1/o21iJRdbquE7gU7PRIzNQKZg6mMqloJxzeh1HDoOq1LIMj0
TSYxX8971lUZVmv7ydWafzLY5JV0FM1tGANhyTuHJtDwVy8qZYiTjl75WQ3CLFof
SsoS3gFR09XhZ/2wKE5sGLGsQvlAA3arPgi9Sv5qUjye3ZpZWrjd0hSVfTNpKDxc
hIoIem892zq0KHnV7xhu1L80b6oQ9ZSGhw7drRMBoljYxNqmn4UYKp0CAwEAAaNj
MGEwHQYDVR0OBBYEFJdliTr9fWgLKbviaYV+yD5Aq9qIMB8GA1UdIwQYMBaAFJdl
iTr9fWgLKbviaYV+yD5Aq9qIMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQD
AgGGMA0GCSqGSIb3DQEBCwUAA4ICAQBXwhW6hoG0ooL6B8Mr6GlqQ40Jesv9lEHS
rhLjd3RpCoK162eL7RJQsZAKfj8wViV2FjD1t0N4L94NnkGo1fuVds3auw1ghrFd
1HEdr37s/nMvpFu6SS4bGwzdYZEEweRr2iQGxPXTXMu+Vu7EDGTXkqDKeSYZoHNX
3GfR0I8eXfNfqW+tdCYzBCOGGTQAHmfyM9YiCnMAQtHQu0ljnBdMhkoBi2EzULAR
lDWBxQE5NmzTCxhd0JHXroKXBvq2Sig2FdKsFIbN9y7colJga6eSN8xARLoLO99q
7dzly9gVOrzBkdX5kRQyzu9CesXbPc0EAqUzj3mXaxeVchZzQ1IlUQO31Mzl5y/z
e1WvQuW1BJQdcIkYp0JVEacYGi6CjjcDphFiaAajRsi7rtiODo8pidMOTXxBitD6
O4MslwSiWvenq5apF9PzvwDndFIfSKzIE6A7/gyKKKuMYz87FTiHipsA/GAOjNUO
8kQ91o6TIF7YTjNS3u8xICa7M8qTxQIHsbsRWzPqAxRnYQkY0aRjO9+5Qqqsg5j4
Pc7TUJiY8gW9SWhPVUPaMkTIBgfN11c6BzLlhzN2r1zaZyghXr8QmcG4kWywkX7k
oXeN5eS8iO5fx0EOvIcYQ4yRZLGafZxsLHlsZmt32N/ZZtcl4KDP5LRE7iZEOaE/
UXY5wAUH2A==
-----END CERTIFICATE-----
`
)

func generateRSAPrivateKey(t *testing.T) *rsa.PrivateKey {
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err)
		t.FailNow()
	}
	return pk
}

func generateCSR(t *testing.T, secretKey crypto.Signer) []byte {
	asn1Subj, _ := asn1.Marshal(pkix.Name{
		CommonName: "test",
	}.ToRDNSequence())
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, secretKey)
	if err != nil {
		t.Errorf("failed to create CSR: %s", err)
		t.FailNow()
	}

	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	return csr
}

type testSignT struct {
	issuer     *cmapi.Issuer
	fakeLister *listers.FakeSecretLister
	fakeClient *vaultfake.Client

	csrPEM       []byte
	expectedErr  error
	expectedCert string
	expectedCA   string
}

func signedCertificateSecret(issuingCaPEM string, caPEM ...string) *certutil.Secret {
	secret := &certutil.Secret{
		Data: map[string]interface{}{
			"certificate": testLeafCertificate,
		},
	}

	secret.Data["issuing_ca"] = issuingCaPEM

	// Vault returns ca_chain only when a certificate chain is set along with a CA certificate to Vault PKI mount
	// See https://github.com/hashicorp/vault/blob/v1.5.0/builtin/logical/pki/path_issue_sign.go#L256
	// See https://github.com/hashicorp/vault/blob/v1.5.5/sdk/helper/certutil/types.go#L627
	if len(caPEM) > 0 {
		chain := []string{issuingCaPEM}
		chain = append(chain, caPEM...)
		secret.Data["ca_chain"] = chain
	}

	return secret
}

func bundlePEM(issuingCaPEM string, caPEM ...string) ([]byte, error) {
	secret := signedCertificateSecret(issuingCaPEM, caPEM...)
	return jsonutil.EncodeJSON(&secret)
}

func TestSign(t *testing.T) {
	privatekey := generateRSAPrivateKey(t)
	csrPEM := generateCSR(t, privatekey)

	bundleData, err := bundlePEM(testIntermediateCa)
	if err != nil {
		t.Errorf("failed to encode bundle for testing: %s", err)
		t.FailNow()
	}

	rootBundleData, err := bundlePEM(testIntermediateCa, testRootCa)
	if err != nil {
		t.Errorf("failed to encode root bundle for testing: %s", err)
		t.FailNow()
	}

	tests := map[string]testSignT{
		"a garbage csr should return err": {
			csrPEM:       []byte("a bad csr"),
			expectedErr:  errors.New("failed to decode CSR for signing: error decoding certificate request PEM block"),
			expectedCert: "",
			expectedCA:   "",
		},

		"a good csr but failed request should error": {
			csrPEM: csrPEM,
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(cmapi.VaultIssuer{}),
			),
			fakeClient:   vaultfake.NewFakeClient().WithRawRequest(nil, errors.New("request failed")),
			expectedErr:  errors.New("failed to sign certificate by vault: request failed"),
			expectedCert: "",
			expectedCA:   "",
		},

		"a good csr and good response with no root should return a certificate with the intermediate in the chain and as the CA": {
			csrPEM: csrPEM,
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(cmapi.VaultIssuer{}),
			),
			fakeClient: vaultfake.NewFakeClient().WithRawRequest(&vault.Response{
				Response: &http.Response{
					Body: io.NopCloser(bytes.NewReader(bundleData))},
			}, nil),
			expectedErr:  nil,
			expectedCert: testLeafCertificate + testIntermediateCa,
			expectedCA:   testIntermediateCa,
		},

		"a good csr and good response with a root should return a certificate without the root in the chain but with the root as the CA": {
			csrPEM: csrPEM,
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(cmapi.VaultIssuer{}),
			),
			fakeClient: vaultfake.NewFakeClient().WithRawRequest(&vault.Response{
				Response: &http.Response{
					Body: io.NopCloser(bytes.NewReader(rootBundleData))},
			}, nil),
			expectedErr:  nil,
			expectedCert: testLeafCertificate + testIntermediateCa,
			expectedCA:   testRootCa,
		},

		"vault issuer with namespace specified": {
			csrPEM: csrPEM,
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(cmapi.VaultIssuer{Namespace: "test"}),
			),
			fakeClient: vaultfake.NewFakeClient().WithRawRequest(&vault.Response{
				Response: &http.Response{
					Body: io.NopCloser(bytes.NewReader(bundleData))},
			}, nil),
			expectedErr:  nil,
			expectedCert: testLeafCertificate + testIntermediateCa,
			expectedCA:   testIntermediateCa,
		},
	}

	for name, test := range tests {
		v := &Vault{
			namespace:     "test-namespace",
			secretsLister: test.fakeLister,
			issuer:        test.issuer,
			client:        test.fakeClient,
		}

		cert, ca, err := v.Sign(test.csrPEM, time.Minute)
		if ((test.expectedErr == nil) != (err == nil)) &&
			test.expectedErr != nil &&
			test.expectedErr.Error() != err.Error() {
			t.Errorf("%s: unexpected error, exp=%v got=%v",
				name, test.expectedErr, err)
		}

		if (test.expectedCert == "" || string(cert) == "") && test.expectedCert != string(cert) {
			t.Errorf("unexpected certificate in response bundle, exp=%s got=%s",
				test.expectedCert, cert)
		} else if test.expectedCert != string(cert) {
			parsedBundle, err := certutil.ParsePEMBundle(string(cert))
			if err != nil {
				t.Errorf("%s: failed to decode bundle: %s", name, err)
			}
			bundle, err := parsedBundle.ToCertBundle()
			if err != nil {
				t.Errorf("%s: failed to convert bundle: %s", name, err)
			}
			if test.expectedCert != bundle.Certificate {
				t.Errorf("%s: unexpected certificate in response bundle, exp=%s got=%s",
					name, test.expectedCert, cert)
			}
		}

		if test.expectedCA != string(ca) {
			t.Errorf("unexpected ca in response bundle, exp=%s got=%s; %s",
				test.expectedCA, ca, name)
		}
	}
}

type testExtractCertificatesFromVaultCertT struct {
	secret       *certutil.Secret
	expectedCert string
	expectedCA   string
}

func TestExtractCertificatesFromVaultCertificateSecret(t *testing.T) {
	tests := map[string]testExtractCertificatesFromVaultCertT{
		"when a Vault engine is a root CA": {
			secret:       signedCertificateSecret(testIntermediateCa),
			expectedCert: testLeafCertificate + testIntermediateCa,
			expectedCA:   testIntermediateCa,
		},
		"when a Vault engine is an intermediate CA, and its parent is a root CA": {
			secret:       signedCertificateSecret(testIntermediateCa, testRootCa),
			expectedCert: testLeafCertificate + testIntermediateCa,
			expectedCA:   testRootCa,
		},
		"when a Vault engine is an intermediate CA, and its parent is a intermediate CA": {
			secret:       signedCertificateSecret(testIntermediateCa, testIntermediateCa, testRootCa),
			expectedCert: testLeafCertificate + testIntermediateCa,
			expectedCA:   testRootCa,
		},
	}

	for name, test := range tests {
		cert, ca, err := extractCertificatesFromVaultCertificateSecret(test.secret)

		if err != nil {
			t.Errorf("%s: failed to extract certificate: %s", name, err)
		}
		if test.expectedCert != string(cert) {
			t.Errorf("%s: unexpected leaf certificate, exp=%q, got=%q", name, test.expectedCert, cert)
		}
		if test.expectedCA != string(ca) {
			t.Errorf("%s: unexpected root certificate, exp=%q, got=%q", name, test.expectedCA, cert)
		}
	}
}

type testSetTokenT struct {
	expectedToken string
	expectedErr   error

	issuer     *cmapi.Issuer
	fakeLister *listers.FakeSecretLister
	fakeClient *vaultfake.Client
}

func TestSetToken(t *testing.T) {
	tokenSecret := &corev1.Secret{
		Data: map[string][]byte{
			"my-token-key": []byte("my-secret-token"),
		},
	}

	appRoleSecret := &corev1.Secret{
		Data: map[string][]byte{
			"my-role-key": []byte("my-secret-role-token"),
		},
	}

	kubeAuthSecret := &corev1.Secret{
		Data: map[string][]byte{
			"my-kube-key": []byte("my-secret-kube-token"),
		},
	}
	tests := map[string]testSetTokenT{
		"if neither token secret ref, app role secret ref, or kube auth then not found then error": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					CABundle: []byte(testLeafCertificate),
					Auth:     cmapi.VaultAuth{},
				}),
			),
			fakeLister:    listers.FakeSecretListerFrom(listers.NewFakeSecretLister()),
			fakeClient:    vaultfake.NewFakeClient(),
			expectedToken: "",
			expectedErr: errors.New(
				"error initializing Vault client: tokenSecretRef, appRoleSecretRef, or Kubernetes auth role not set",
			),
		},

		"if token secret ref is set but secret doesn't exist should error": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					CABundle: []byte(testLeafCertificate),
					Auth: cmapi.VaultAuth{
						TokenSecretRef: &cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "secret-ref-name",
							},
						},
					},
				}),
			),
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, errors.New("secret does not exists")),
			),
			fakeClient:    vaultfake.NewFakeClient(),
			expectedToken: "",
			expectedErr:   errors.New("secret does not exists"),
		},

		"if token secret ref set, return client using token stored": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					CABundle: []byte(testLeafCertificate),
					Auth: cmapi.VaultAuth{
						TokenSecretRef: &cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "secret-ref-name",
							},
							Key: "my-token-key",
						},
					},
				}),
			),
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(tokenSecret, nil),
			),
			fakeClient:    vaultfake.NewFakeClient(),
			expectedToken: "my-secret-token",
			expectedErr:   nil,
		},

		"if app role set but secret token not but vault fails to return token, error": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					CABundle: []byte(testLeafCertificate),
					Auth: cmapi.VaultAuth{
						AppRole: &cmapi.VaultAppRole{
							RoleId: "my-role-id",
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-ref-name",
								},
								Key: "my-role-key",
							},
						},
					},
				}),
			),
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, errors.New("secret not found")),
			),
			fakeClient:    vaultfake.NewFakeClient(),
			expectedToken: "",
			expectedErr:   errors.New("secret not found"),
		},

		"if app role secret ref set, return client using token stored": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					CABundle: []byte(testLeafCertificate),
					Auth: cmapi.VaultAuth{
						AppRole: &cmapi.VaultAppRole{
							RoleId: "my-role-id",
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-ref-name",
								},
								Key: "my-role-key",
							},
						},
					},
				}),
			),
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(appRoleSecret, nil),
			),
			fakeClient: vaultfake.NewFakeClient().WithRawRequest(&vault.Response{
				Response: &http.Response{
					Body: io.NopCloser(
						strings.NewReader(
							`{"request_id":"","lease_id":"","lease_duration":0,"renewable":false,"data":null,"warnings":null,"data":{"id":"my-roleapp-token"}}`),
					),
				},
			}, nil),
			expectedToken: "my-roleapp-token",
			expectedErr:   nil,
		},

		"if kubernetes role auth set but reference secret doesn't exist return error": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					CABundle: []byte(testLeafCertificate),
					Auth: cmapi.VaultAuth{
						Kubernetes: &cmapi.VaultKubernetesAuth{
							Role: "kube-vault-role",
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-ref-name",
								},
								Key: "my-kube-key",
							},
						},
					},
				}),
			),
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, errors.New("secret does not exists")),
			),
			fakeClient:    vaultfake.NewFakeClient(),
			expectedToken: "",
			expectedErr:   errors.New("error reading Kubernetes service account token from secret-ref-name: secret does not exists"),
		},

		"if kubernetes role auth set but reference secret doesn't contain data at key error": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					CABundle: []byte(testLeafCertificate),
					Auth: cmapi.VaultAuth{
						Kubernetes: &cmapi.VaultKubernetesAuth{
							Role: "kube-vault-role",
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-ref-name",
								},
								Key: "my-kube-key",
							},
						},
					},
				}),
			),
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(&corev1.Secret{}, nil),
			),
			fakeClient:    vaultfake.NewFakeClient(),
			expectedToken: "",
			expectedErr:   errors.New(`error reading Kubernetes service account token from secret-ref-name: no data for "my-kube-key" in secret 'test-namespace/secret-ref-name'`),
		},

		"if kubernetes role auth set but errors with a raw request should error": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					CABundle: []byte(testLeafCertificate),
					Auth: cmapi.VaultAuth{
						Kubernetes: &cmapi.VaultKubernetesAuth{
							Role: "kube-vault-role",
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-ref-name",
								},
								Key: "my-kube-key",
							},
						},
					},
				}),
			),
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(kubeAuthSecret, nil),
			),
			fakeClient:    vaultfake.NewFakeClient().WithRawRequest(nil, errors.New("raw request error")),
			expectedToken: "",
			expectedErr:   errors.New("error reading Kubernetes service account token from secret-ref-name: error calling Vault server: raw request error"),
		},

		"foo": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					CABundle: []byte(testLeafCertificate),
					Auth: cmapi.VaultAuth{
						Kubernetes: &cmapi.VaultKubernetesAuth{
							Role: "kube-vault-role",
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-ref-name",
								},
								Key: "my-kube-key",
							},
						},
					},
				}),
			),
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(kubeAuthSecret, nil),
			),
			fakeClient: vaultfake.NewFakeClient().WithRawRequest(&vault.Response{
				Response: &http.Response{
					Body: io.NopCloser(
						strings.NewReader(
							`{"request_id":"","lease_id":"","lease_duration":0,"renewable":false,"data":null,"warnings":null,"data":{"id":"my-token"}}`),
					),
				},
			}, nil),
			expectedToken: "my-token",
			expectedErr:   nil,
		},

		"if app role secret ref and token secret set, take preference on token secret": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					CABundle: []byte(testLeafCertificate),
					Auth: cmapi.VaultAuth{
						AppRole: &cmapi.VaultAppRole{
							RoleId: "my-role-id",
							SecretRef: cmmeta.SecretKeySelector{
								LocalObjectReference: cmmeta.LocalObjectReference{
									Name: "secret-ref-name",
								},
								Key: "my-role-key",
							},
						},
						TokenSecretRef: &cmmeta.SecretKeySelector{
							LocalObjectReference: cmmeta.LocalObjectReference{
								Name: "secret-ref-name",
							},
							Key: "my-token-key",
						},
					},
				}),
			),
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(tokenSecret, nil),
			),
			fakeClient:    vaultfake.NewFakeClient(),
			expectedToken: "my-secret-token",
			expectedErr:   nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			v := &Vault{
				namespace:     "test-namespace",
				secretsLister: test.fakeLister,
				issuer:        test.issuer,
			}

			err := v.setToken(test.fakeClient)
			if ((test.expectedErr == nil) != (err == nil)) &&
				test.expectedErr != nil &&
				test.expectedErr.Error() != err.Error() {
				t.Errorf("unexpected error, exp=%v got=%v",
					test.expectedErr, err)
			}

			if test.fakeClient.Token() != test.expectedToken {
				t.Errorf("got unexpected client token, exp=%s got=%s",
					test.expectedToken, test.fakeClient.Token())
			}
		})
	}
}

type testAppRoleRefT struct {
	expectedRoleID   string
	expectedSecretID string
	expectedErr      error

	appRole *cmapi.VaultAppRole

	fakeLister *listers.FakeSecretLister
}

func TestAppRoleRef(t *testing.T) {
	errSecretGet := errors.New("no secret found")

	basicAppRoleRef := &cmapi.VaultAppRole{
		RoleId: "my-role-id",
	}

	tests := map[string]testAppRoleRefT{
		"failing to get secret should error": {
			appRole: basicAppRoleRef,
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, errSecretGet),
			),
			expectedRoleID:   "",
			expectedSecretID: "",
			expectedErr:      errSecretGet,
		},

		"no data in key should fail": {
			appRole: &cmapi.VaultAppRole{
				RoleId: "",
				SecretRef: cmmeta.SecretKeySelector{
					LocalObjectReference: cmmeta.LocalObjectReference{
						Name: "secret-name",
					},
					Key: "my-key",
				},
			},
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(
					&corev1.Secret{
						Data: map[string][]byte{
							"foo": []byte("bar"),
						},
					}, nil),
			),
			expectedRoleID:   "",
			expectedSecretID: "",
			expectedErr:      errors.New(`no data for "my-key" in secret 'test-namespace/secret-name'`),
		},

		"should return roleID and secretID with trimmed space": {
			appRole: &cmapi.VaultAppRole{
				RoleId: "    my-role-id  ",
				SecretRef: cmmeta.SecretKeySelector{
					LocalObjectReference: cmmeta.LocalObjectReference{
						Name: "secret-name",
					},
					Key: "my-key",
				},
			},
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(
					&corev1.Secret{
						Data: map[string][]byte{
							"foo":    []byte("bar"),
							"my-key": []byte("    my-key-data   "),
						},
					}, nil),
			),
			expectedRoleID:   "my-role-id",
			expectedSecretID: "my-key-data",
			expectedErr:      nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			v := &Vault{
				namespace:     "test-namespace",
				secretsLister: test.fakeLister,
				issuer:        nil,
			}

			roleID, secretID, err := v.appRoleRef(test.appRole)
			if ((test.expectedErr == nil) != (err == nil)) &&
				test.expectedErr != nil &&
				test.expectedErr.Error() != err.Error() {
				t.Errorf("unexpected error, exp=%v got=%v",
					test.expectedErr, err)
			}

			if test.expectedRoleID != roleID {
				t.Errorf("got unexpected roleID, exp=%s got=%s",
					test.expectedRoleID, roleID)
			}

			if test.expectedSecretID != secretID {
				t.Errorf("got unexpected secretID, exp=%s got=%s",
					test.expectedSecretID, secretID)
			}
		})
	}
}

type testTokenRefT struct {
	expectedToken string
	expectedErr   error

	key string

	fakeLister *listers.FakeSecretLister
}

func TestTokenRef(t *testing.T) {
	errSecretGet := errors.New("no secret found")

	testName, testNamespace := "test-name", "test-namespace"

	tests := map[string]testTokenRefT{
		"failing to get secret should error": {
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, errSecretGet),
			),
			key:           "a-key",
			expectedToken: "",
			expectedErr:   errSecretGet,
		},

		"if no vault at key exists then error": {
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(
					&corev1.Secret{
						Data: map[string][]byte{
							"foo": []byte("bar"),
						},
					}, nil),
			),

			key:           "a-key",
			expectedToken: "",
			expectedErr: fmt.Errorf(`no data for "a-key" in secret '%s/%s'`,
				testName, testNamespace),
		},
		"if value exists at key then return with whitespace trimmed": {
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(
					&corev1.Secret{
						Data: map[string][]byte{
							"foo":   []byte("bar"),
							"a-key": []byte(" my-token              "),
						},
					}, nil),
			),

			key:           "a-key",
			expectedToken: "my-token",
		},
		"if no key is given then it should default to 'token'": {
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(
					&corev1.Secret{
						Data: map[string][]byte{
							"foo":   []byte("bar"),
							"token": []byte(" my-token              "),
						},
					}, nil),
			),

			key:           "",
			expectedToken: "my-token",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			v := &Vault{
				namespace:     "test-namespace",
				secretsLister: test.fakeLister,
				issuer:        nil,
			}

			token, err := v.tokenRef("test-name", "test-namespace", test.key)
			if ((test.expectedErr == nil) != (err == nil)) &&
				test.expectedErr != nil &&
				test.expectedErr.Error() != err.Error() {
				t.Errorf("unexpected error, exp=%v got=%v",
					test.expectedErr, err)
			}

			if test.expectedToken != token {
				t.Errorf("got unexpected token, exp=%s got=%s",
					test.expectedToken, token)
			}
		})
	}
}

type testNewConfigT struct {
	expectedErr error
	issuer      *cmapi.Issuer
	checkFunc   func(cfg *vault.Config, err error) error

	fakeLister *listers.FakeSecretLister
}

func TestNewConfig(t *testing.T) {
	caBundleSecretRefFakeSecretLister := func(namespace, secret, key, cert string) *listers.FakeSecretLister {
		return listers.FakeSecretListerFrom(listers.NewFakeSecretLister(), func(f *listers.FakeSecretLister) {
			f.SecretsFn = func(namespace string) clientcorev1.SecretNamespaceLister {
				return listers.FakeSecretNamespaceListerFrom(listers.NewFakeSecretNamespaceLister(), func(fn *listers.FakeSecretNamespaceLister) {
					fn.GetFn = func(name string) (*corev1.Secret, error) {
						if name == secret && namespace == namespace {
							return &corev1.Secret{
								Data: map[string][]byte{
									key: []byte(cert),
								}}, nil
						}
						return nil, errors.New("unexpected secret name or namespace passed to FakeSecretLister")
					}
				})
			}
		})
	}
	tests := map[string]testNewConfigT{
		"no CA bundle set in issuer should return nil": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					CABundle: nil,
				}),
			),
			expectedErr: nil,
		},

		"a bad cert bundle should error": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					CABundle: []byte("a bad cert bundle"),
				}),
			),
			expectedErr: errors.New("no Vault CA bundles loaded, check bundle contents"),
		},

		"a good cert bundle should be added to the config": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					CABundle: []byte(testLeafCertificate),
				}),
			),
			expectedErr: nil,
			checkFunc: func(cfg *vault.Config, error error) error {
				testCA := x509.NewCertPool()
				testCA.AppendCertsFromPEM([]byte(testLeafCertificate))
				subs := cfg.HttpClient.Transport.(*http.Transport).TLSClientConfig.RootCAs.Subjects()

				err := fmt.Errorf("got unexpected root CAs in config, exp=%s got=%s",
					testCA.Subjects(), subs)
				if len(subs) != len(testCA.Subjects()) {
					return err
				}
				for i := range subs {
					if !bytes.Equal(subs[i], testCA.Subjects()[i]) {
						return err
					}
				}

				return nil
			},
		},

		"a good bundle from a caBundleSecretRef should be added to the config": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					CABundleSecretRef: &cmmeta.SecretKeySelector{
						Key: "my-bundle.crt",
						LocalObjectReference: cmmeta.LocalObjectReference{
							Name: "bundle",
						},
					},
				},
				)),
			checkFunc: func(cfg *vault.Config, error error) error {
				if error != nil {
					return error
				}

				testCA := x509.NewCertPool()
				testCA.AppendCertsFromPEM([]byte(testLeafCertificate))
				subs := cfg.HttpClient.Transport.(*http.Transport).TLSClientConfig.RootCAs.Subjects()

				err := fmt.Errorf("got unexpected root CAs in config, exp=%s got=%s",
					testCA.Subjects(), subs)
				if len(subs) != len(testCA.Subjects()) {
					return err
				}
				for i := range subs {
					if !bytes.Equal(subs[i], testCA.Subjects()[i]) {
						return err
					}
				}

				return nil
			},
			fakeLister: caBundleSecretRefFakeSecretLister("test-namespace", "bundle", "my-bundle.crt", testLeafCertificate),
		},
		"a good bundle from a caBundleSecretRef with default key should be added to the config": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					CABundleSecretRef: &cmmeta.SecretKeySelector{
						LocalObjectReference: cmmeta.LocalObjectReference{
							Name: "bundle",
						},
					},
				},
				)),
			checkFunc: func(cfg *vault.Config, error error) error {
				if error != nil {
					return error
				}

				testCA := x509.NewCertPool()
				testCA.AppendCertsFromPEM([]byte(testLeafCertificate))
				subs := cfg.HttpClient.Transport.(*http.Transport).TLSClientConfig.RootCAs.Subjects()

				err := fmt.Errorf("got unexpected root CAs in config, exp=%s got=%s",
					testCA.Subjects(), subs)
				if len(subs) != len(testCA.Subjects()) {
					return err
				}
				for i := range subs {
					if !bytes.Equal(subs[i], testCA.Subjects()[i]) {
						return err
					}
				}

				return nil
			},
			fakeLister: caBundleSecretRefFakeSecretLister("test-namespace", "bundle", "ca.crt", testLeafCertificate),
		},
		"a bad bundle from a caBundleSecretRef should error": {
			issuer: gen.Issuer("vault-issuer",
				gen.SetIssuerVault(cmapi.VaultIssuer{
					CABundleSecretRef: &cmmeta.SecretKeySelector{
						Key: "my-bundle.crt",
						LocalObjectReference: cmmeta.LocalObjectReference{
							Name: "bundle",
						},
					},
				},
				)),
			expectedErr: errors.New("no Vault CA bundles loaded, check bundle contents"),
			fakeLister:  caBundleSecretRefFakeSecretLister("test-namespace", "bundle", "my-bundle.crt", "not a valid certificate"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			v := &Vault{
				namespace:     "test-namespace",
				secretsLister: test.fakeLister,
				issuer:        test.issuer,
			}

			cfg, err := v.newConfig()
			if test.expectedErr != nil && err != nil && test.expectedErr.Error() != err.Error() {
				t.Errorf("unexpected error, exp=%v got=%v", test.expectedErr, err)
			}

			if test.checkFunc != nil {
				if err := test.checkFunc(cfg, err); err != nil {
					t.Errorf("check function failed: %s", err)
				}
			}
		})
	}
}

type requestTokenWithAppRoleRefT struct {
	client  Client
	appRole *cmapi.VaultAppRole

	fakeLister *listers.FakeSecretLister

	expectedToken string
	expectedErr   error
}

func TestRequestTokenWithAppRoleRef(t *testing.T) {
	basicAppRoleRef := &cmapi.VaultAppRole{
		RoleId: "test-role-id",
		SecretRef: cmmeta.SecretKeySelector{
			LocalObjectReference: cmmeta.LocalObjectReference{
				Name: "test-secret",
			},
			Key: "my-key",
		},
	}

	basicSecretLister := listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
		listers.SetFakeSecretNamespaceListerGet(
			&corev1.Secret{
				Data: map[string][]byte{
					"my-key": []byte("my-key-data"),
				},
			}, nil),
	)

	tests := map[string]requestTokenWithAppRoleRefT{
		"a secret reference that does not exist should error": {
			client:  vaultfake.NewFakeClient(),
			appRole: basicAppRoleRef,
			fakeLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, errors.New("secret not found")),
			),

			expectedToken: "",
			expectedErr:   errors.New("secret not found"),
		},
		"if a raw request fails then error": {
			client:     vaultfake.NewFakeClient().WithRawRequest(nil, errors.New("request failed")),
			appRole:    basicAppRoleRef,
			fakeLister: basicSecretLister,

			expectedToken: "",
			expectedErr:   errors.New("error logging in to Vault server: request failed"),
		},
		"no id in the JSON response should return no token": {
			client: vaultfake.NewFakeClient().WithRawRequest(
				&vault.Response{
					Response: &http.Response{
						Body: io.NopCloser(
							strings.NewReader(
								`{"request_id":"","lease_id":"","lease_duration":0,"renewable":false,"data":null,"warnings":null,"data":{}}`),
						),
					},
				}, nil,
			),
			appRole:    basicAppRoleRef,
			fakeLister: basicSecretLister,

			expectedToken: "",
			expectedErr:   errors.New("no token returned"),
		},
		"an id in the JSON response should return that token": {
			client: vaultfake.NewFakeClient().WithRawRequest(
				&vault.Response{
					Response: &http.Response{
						Body: io.NopCloser(
							strings.NewReader(
								`{"request_id":"","lease_id":"","lease_duration":0,"renewable":false,"data":null,"warnings":null,"data":{"id":"my-token"}}`),
						),
					},
				}, nil,
			),
			appRole:    basicAppRoleRef,
			fakeLister: basicSecretLister,

			expectedToken: "my-token",
			expectedErr:   nil,
		},
		"a client_token present should take president over id": {
			client: vaultfake.NewFakeClient().WithRawRequest(
				&vault.Response{
					Response: &http.Response{
						Body: io.NopCloser(
							strings.NewReader(
								`{"request_id":"","lease_id":"","lease_duration":0,"renewable":false,"data":null,"warnings":null,"data":{"id":"my-token"},"auth":{"client_token":"my-client-token"}}`),
						),
					},
				}, nil,
			),
			appRole:    basicAppRoleRef,
			fakeLister: basicSecretLister,

			expectedToken: "my-client-token",
			expectedErr:   nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			v := &Vault{
				namespace:     "test-namespace",
				secretsLister: test.fakeLister,
				issuer: gen.Issuer("vault-issuer",
					gen.SetIssuerNamespace("namespace"),
				),
			}

			token, err := v.requestTokenWithAppRoleRef(test.client, test.appRole)
			if ((test.expectedErr == nil) != (err == nil)) &&
				test.expectedErr != nil &&
				test.expectedErr.Error() != err.Error() {
				t.Errorf("unexpected error, exp=%v got=%v",
					test.expectedErr, err)
			}

			if test.expectedToken != token {
				t.Errorf("got unexpected token, exp=%s got=%s",
					test.expectedToken, token)
			}
		})
	}
}
