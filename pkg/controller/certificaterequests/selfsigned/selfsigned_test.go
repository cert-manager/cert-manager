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
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientcorev1 "k8s.io/client-go/listers/core/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	testfake "github.com/jetstack/cert-manager/pkg/controller/test/fake"
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

func mustNoResponse(builder *testpkg.Builder, args ...interface{}) {
	resp := args[0].(*issuer.IssueResponse)
	if resp != nil {
		builder.T.Errorf("unexpected response, exp='nil' got='%+v'", resp)
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

	tests := map[string]testT{
		"a CertificateRequest with no certmanager.k8s.io/selfsigned-private-key annotation should record pending": {
			// no annotation
			certificaterequest: gen.CertificateRequest("test-cr"),
			builder: &testpkg.Builder{
				ExpectedEvents: []string{
					`Normal MissingAnnotation Annotation "certmanager.k8s.io/private-key-secret-name" missing or reference empty: self signed issuer requires "certmanager.k8s.io/private-key-secret-name" annotation to be set to the name of the Secret containing the private key`,
				},
				CheckFn: mustNoResponse,
			},
			expectedErr: false,
		},
		"a CertificateRequest with a certmanager.k8s.io/private-key-secret-name annotation but empty string should record pending": {
			// no data in annotation
			certificaterequest: gen.CertificateRequest("test-cr",
				gen.AddCertificateRequestAnnotations(map[string]string{
					v1alpha1.CRPrivateKeyAnnotationKey: "",
				}),
			),
			builder: &testpkg.Builder{
				ExpectedEvents: []string{
					`Normal MissingAnnotation Annotation "certmanager.k8s.io/private-key-secret-name" missing or reference empty: self signed issuer requires "certmanager.k8s.io/private-key-secret-name" annotation to be set to the name of the Secret containing the private key`,
				},
				CheckFn: mustNoResponse,
			},
			expectedErr: false,
		},
		"a CertificateRequest with a certmanager.k8s.io/private-key-secret-name annotation but the referenced secret doesn't exist should record pending": {
			certificaterequest: gen.CertificateRequest("test-cr",
				gen.AddCertificateRequestAnnotations(map[string]string{
					v1alpha1.CRPrivateKeyAnnotationKey: "a-non-existent-secret",
				}),
			),
			builder: &testpkg.Builder{
				ExpectedEvents: []string{
					`Normal MissingSecret Referenced secret default-unit-test-ns/a-non-existent-secret not found: secret "a-non-existent-secret" not found`,
				},
				CheckFn: mustNoResponse,
			},
			expectedErr: false,
		},
		"a CertificateRequest with a bad CSR should fail": {
			certificaterequest: gen.CertificateRequest("test-cr",
				gen.AddCertificateRequestAnnotations(map[string]string{
					v1alpha1.CRPrivateKeyAnnotationKey: "test-rsa-key",
				}),
				gen.SetCertificateRequestCSR([]byte("this is a bad CSR")),
			),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{rsaKeySecret},
				ExpectedEvents: []string{
					"Warning ErrorGenerating Failed to generate certificate template: failed to decode csr from certificate request resource default-unit-test-ns/test-cr",
				},
				CheckFn: mustNoResponse,
			},
			expectedErr: false,
		},
		"a CertificateRequest referencing a bad key should record pending": {
			certificaterequest: gen.CertificateRequest("test-cr",
				gen.AddCertificateRequestAnnotations(map[string]string{
					v1alpha1.CRPrivateKeyAnnotationKey: "test-bad-key",
				}),
				gen.SetCertificateRequestCSR(csrBytes),
			),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{badKeySecret},
				CheckFn:     mustNoResponse,
				ExpectedEvents: []string{
					`Normal ErrorParsingKey Failed to get key "test-bad-key" referenced in annotation "certmanager.k8s.io/private-key-secret-name": error decoding private key PEM block`,
				},
			},
			expectedErr: false,
		},
		"a CertificateRequest that transiently fails a secret lookup should backoff error to retry": {
			certificaterequest: gen.CertificateRequest("test-cr",
				gen.AddCertificateRequestAnnotations(map[string]string{
					v1alpha1.CRPrivateKeyAnnotationKey: "test-rsa-key",
				}),
				gen.SetCertificateRequestCSR(csrBytes),
			),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{rsaKeySecret},
				CheckFn:     mustNoResponse,
				ExpectedEvents: []string{
					`Normal ErrorGettingSecret Failed to get key "test-rsa-key" referenced in annotation "certmanager.k8s.io/private-key-secret-name": this is a network error`,
				},
			},
			FakeLister: &testfake.FakeSecretLister{
				SecretsFn: func(namespace string) clientcorev1.SecretNamespaceLister {
					return &testfake.FakeSecretNamespaceLister{
						GetFn: func(name string) (ret *corev1.Secret, err error) {
							return nil, errors.New("this is a network error")
						},
					}
				},
			},
			expectedErr: true,
		},
		"a CertificateRequest referencing a key which did not sign the CSR should fail": {
			certificaterequest: gen.CertificateRequest("test-cr",
				gen.AddCertificateRequestAnnotations(map[string]string{
					v1alpha1.CRPrivateKeyAnnotationKey: "test-another-rsa-key",
				}),
				gen.SetCertificateRequestCSR(csrBytes),
			),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{anotherRSAKeySecret},
				ExpectedEvents: []string{
					"Warning ErrorKeyMatch Error generating certificate template: CSR not signed by referenced private key",
				},
				CheckFn: mustNoResponse,
			},
			expectedErr: false,
		},
		"a valid RSA key should sign a self signed certificate": {
			certificaterequest: gen.CertificateRequest("test-cr",
				gen.AddCertificateRequestAnnotations(map[string]string{
					v1alpha1.CRPrivateKeyAnnotationKey: "test-rsa-key",
				}),
				gen.SetCertificateRequestCSR(csrBytes),
			),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{rsaKeySecret},
				CheckFn: func(builder *testpkg.Builder, args ...interface{}) {
					resp := args[0].(*issuer.IssueResponse)

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
			expectedErr: false,
		},
		"a valid ECDSA key should sign a self signed certificate": {
			certificaterequest: gen.CertificateRequest("test-cr",
				gen.AddCertificateRequestAnnotations(map[string]string{
					v1alpha1.CRPrivateKeyAnnotationKey: "test-ecdsa-key",
				}),
				gen.SetCertificateRequestCSR(csrECBytes),
			),
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{ecKeySecret},
				CheckFn: func(builder *testpkg.Builder, args ...interface{}) {
					resp := args[0].(*issuer.IssueResponse)
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
			expectedErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			runTest(t, test)
		})
	}
}

type testT struct {
	builder            *testpkg.Builder
	certificaterequest *v1alpha1.CertificateRequest

	checkFn     func(*testpkg.Builder, ...interface{})
	expectedErr bool

	FakeLister *testfake.FakeSecretLister
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Start()
	defer test.builder.Stop()

	c := NewSelfSigned(test.builder.Context)

	if test.FakeLister != nil {
		c.secretsLister = test.FakeLister
	}

	test.builder.Sync()

	resp, err := c.Sign(context.Background(), test.certificaterequest)
	if err != nil && !test.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && test.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}
	test.builder.CheckAndFinish(resp, err)
}
