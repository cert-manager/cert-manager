/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package selfsigned

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

func generateCSR(t *testing.T, secretKey crypto.Signer, alg x509.SignatureAlgorithm) []byte {
	asn1Subj, _ := asn1.Marshal(pkix.Name{
		CommonName: "test",
	}.ToRDNSequence())
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: alg,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, secretKey)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	return csr
}

func mustNoResponse(t *testing.T, args []interface{}) {
	resp := args[1].(*issuer.IssueResponse)
	if resp != nil {
		t.Errorf("unexpected response, exp='nil' got='%+v'", resp)
	}
}

func TestSign(t *testing.T) {
	skRSA, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Errorf("failed to generate RSA private key: %s", err)
		t.FailNow()
	}

	skEC, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		t.Errorf("failed to generate ECDA private key: %s", err)
		t.FailNow()
	}

	skAnotherRSA, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Errorf("failed to generate RSA private key: %s", err)
		t.FailNow()
	}

	csrBytes := generateCSR(t, skRSA, x509.SHA256WithRSA)
	csrECBytes := generateCSR(t, skEC, x509.ECDSAWithSHA256)

	skRSAPEMBytes := pki.EncodePKCS1PrivateKey(skRSA)
	skAnotherRSAPEMBytes := pki.EncodePKCS1PrivateKey(skAnotherRSA)
	skECPEMBytes, err := pki.EncodeECPrivateKey(skEC)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	rsaKeySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rsa-key",
			Namespace: gen.DefaultTestNamespace,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: skRSAPEMBytes,
		},
	}
	anotherRSAKeySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-another-rsa-key",
			Namespace: gen.DefaultTestNamespace,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: skAnotherRSAPEMBytes,
		},
	}
	ecKeySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ecdsa-key",
			Namespace: gen.DefaultTestNamespace,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: skECPEMBytes,
		},
	}
	badKeySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-bad-key",
			Namespace: gen.DefaultTestNamespace,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: []byte("this is a bad key"),
		},
	}

	tests := map[string]selfsignedFixture{
		"a CertificateRequest with no certmanager.k8s.io/selfsigned-private-key annotation should record error": {
			Issuer: gen.Issuer("selfsigned-issuer",
				gen.SetIssuerSelfSigned(v1alpha1.SelfSignedIssuer{}),
			),
			// no data in annotation
			CertificateRequest: gen.CertificateRequest("test-cr"),
			Builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{},
				ExpectedEvents: []string{
					"Warning ErrorAnnotation Referenced secret default-unit-test-ns/ not found: self signed issuer requires 'certmanager.k8s.io/private-key-secret-name' annotation set to secret name holding the private key",
				},
			},
			Err: false,
			CheckFn: func(t *testing.T, s *selfsignedFixture, args ...interface{}) {
				mustNoResponse(t, args)
			},
		},
		"a CertificateRequest with a certmanager.k8s.io/private-key-secret-name annotation but empty string should record error": {
			Issuer: gen.Issuer("selfsigned-issuer",
				gen.SetIssuerSelfSigned(v1alpha1.SelfSignedIssuer{}),
			),
			// no data in annotation
			CertificateRequest: gen.CertificateRequest("test-cr",
				gen.AddCertificateRequestAnnotations(map[string]string{
					v1alpha1.CRPrivateKeyAnnotationKey: "",
				}),
			),
			Builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{},
				ExpectedEvents: []string{
					"Warning ErrorAnnotation Referenced secret default-unit-test-ns/ not found: self signed issuer requires 'certmanager.k8s.io/private-key-secret-name' annotation set to secret name holding the private key",
				},
			},
			Err: false,
			CheckFn: func(t *testing.T, s *selfsignedFixture, args ...interface{}) {
			},
		},
		"a CertificateRequest with a certmanager.k8s.io/private-key-secret-name annotation but the referenced secret doesn't exist should record error": {
			Issuer: gen.Issuer("selfsigned-issuer",
				gen.SetIssuerSelfSigned(v1alpha1.SelfSignedIssuer{}),
			),
			CertificateRequest: gen.CertificateRequest("test-cr",
				gen.AddCertificateRequestAnnotations(map[string]string{
					v1alpha1.CRPrivateKeyAnnotationKey: "a-non-existent-secret",
				}),
			),
			Builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{},
				CertManagerObjects: []runtime.Object{},
				ExpectedEvents: []string{
					`Warning ErrorSecret Referenced secret default-unit-test-ns/a-non-existent-secret not found: secret "a-non-existent-secret" not found`,
				},
			},
			Err: false,
			CheckFn: func(t *testing.T, s *selfsignedFixture, args ...interface{}) {
			},
		},
		"a CertificateRequest with a bad CSR should error": {
			Issuer: gen.Issuer("selfsigned-issuer",
				gen.SetIssuerSelfSigned(v1alpha1.SelfSignedIssuer{}),
			),
			CertificateRequest: gen.CertificateRequest("test-cr",
				gen.AddCertificateRequestAnnotations(map[string]string{
					v1alpha1.CRPrivateKeyAnnotationKey: "test-rsa-key",
				}),
				gen.SetCertificateRequestCSR([]byte("this is a bad CSR")),
			),
			Builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{rsaKeySecret},
				CertManagerObjects: []runtime.Object{},
				ExpectedEvents: []string{
					"Warning ErrorGenerating Failed to generate certificate template: failed to decode csr from certificate request resource default-unit-test-ns/test-cr",
				},
			},
			Err: false,
			CheckFn: func(t *testing.T, s *selfsignedFixture, args ...interface{}) {
			},
		},
		"a CertificateRequest referencing a bad key should record an error": {
			Issuer: gen.Issuer("selfsigned-issuer",
				gen.SetIssuerSelfSigned(v1alpha1.SelfSignedIssuer{}),
			),
			CertificateRequest: gen.CertificateRequest("test-cr",
				gen.AddCertificateRequestAnnotations(map[string]string{
					v1alpha1.CRPrivateKeyAnnotationKey: "test-bad-key",
				}),
				gen.SetCertificateRequestCSR(csrBytes),
			),
			Builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{badKeySecret},
				CertManagerObjects: []runtime.Object{},
			},
			Err: true,
			CheckFn: func(t *testing.T, s *selfsignedFixture, args ...interface{}) {
				badKeyError := "failed to get private key test-bad-key referenced in the annotation 'certmanager.k8s.io/private-key-secret-name': error decoding private key PEM block"
				err := args[2].(error)
				if err == nil || err.Error() != badKeyError {
					t.Errorf("unexpected error, exp='%s' got='%+v'", badKeyError, err)
				}
			},
		},
		"a CertificateRequest referencing a key which did not sign the CSR should record an error": {
			Issuer: gen.Issuer("selfsigned-issuer",
				gen.SetIssuerSelfSigned(v1alpha1.SelfSignedIssuer{}),
			),
			CertificateRequest: gen.CertificateRequest("test-cr",
				gen.AddCertificateRequestAnnotations(map[string]string{
					v1alpha1.CRPrivateKeyAnnotationKey: "test-another-rsa-key",
				}),
				gen.SetCertificateRequestCSR(csrBytes),
			),
			Builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{anotherRSAKeySecret},
				CertManagerObjects: []runtime.Object{},
				ExpectedEvents: []string{
					"Warning ErrorKeyMatch Error generating certificate template: CSR not signed by referenced private key",
				},
			},
			Err: false,
			CheckFn: func(t *testing.T, s *selfsignedFixture, args ...interface{}) {
			},
		},
		"a valid RSA key should sign a self signed certificate": {
			Issuer: gen.Issuer("selfsigned-issuer",
				gen.SetIssuerSelfSigned(v1alpha1.SelfSignedIssuer{}),
			),
			CertificateRequest: gen.CertificateRequest("test-cr",
				gen.AddCertificateRequestAnnotations(map[string]string{
					v1alpha1.CRPrivateKeyAnnotationKey: "test-rsa-key",
				}),
				gen.SetCertificateRequestCSR(csrBytes),
			),
			Builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{rsaKeySecret},
				CertManagerObjects: []runtime.Object{},
			},
			Err: false,
			CheckFn: func(t *testing.T, s *selfsignedFixture, args ...interface{}) {
				resp := args[1].(*issuer.IssueResponse)

				// CA and cert should be the same.
				if !bytes.Equal(resp.CA, resp.Certificate) {
					t.Errorf("expected CA and cert to be the same but got:\nCA: %s\nCert: %s",
						resp.CA, resp.Certificate)
				}

				// No private key should be returned.
				if len(resp.PrivateKey) > 0 {
					t.Errorf("expected to private key returned but got: %s",
						resp.PrivateKey)
				}
			},
		},
		"a valid ECDSA key should sign a self signed certificate": {
			Issuer: gen.Issuer("selfsigned-issuer",
				gen.SetIssuerSelfSigned(v1alpha1.SelfSignedIssuer{}),
			),
			CertificateRequest: gen.CertificateRequest("test-cr",
				gen.AddCertificateRequestAnnotations(map[string]string{
					v1alpha1.CRPrivateKeyAnnotationKey: "test-ecdsa-key",
				}),
				gen.SetCertificateRequestCSR(csrECBytes),
			),
			Builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{ecKeySecret},
				CertManagerObjects: []runtime.Object{},
			},
			Err: false,
			CheckFn: func(t *testing.T, s *selfsignedFixture, args ...interface{}) {
				resp := args[1].(*issuer.IssueResponse)
				if resp == nil {
					t.Errorf("expected a response but got: %+v",
						args[1])
					return
				}

				// CA and cert should be the same.
				if !bytes.Equal(resp.CA, resp.Certificate) {
					t.Errorf("expected CA and cert to be the same but got:\nCA: %s\nCert: %s",
						resp.CA, resp.Certificate)
				}

				// No private key should be returned.
				if len(resp.PrivateKey) > 0 {
					t.Errorf("expected to private key returned but got: %s",
						resp.PrivateKey)
				}
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if test.Builder == nil {
				test.Builder = &testpkg.Builder{}
			}

			test.Setup(t)
			crCopy := test.CertificateRequest.DeepCopy()
			resp, err := test.SelfSigned.Sign(test.Ctx, crCopy)
			if err != nil && !test.Err {
				t.Errorf("Expected function to not error, but got: %v", err)
			}
			if err == nil && test.Err {
				t.Errorf("Expected function to get an error, but got: %v", err)
			}

			test.Finish(t, crCopy, resp, err)
		})
	}
}
