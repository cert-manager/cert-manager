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

package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

func generateRSAPrivateKey(t *testing.T) *rsa.PrivateKey {
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err)
		t.FailNow()
	}
	return pk
}

func generateECDSAPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	pk, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err)
		t.FailNow()
	}
	return pk
}

func generateSelfSignedCert(t *testing.T, crt *v1alpha1.Certificate, key crypto.Signer, duration time.Duration) (derBytes, pemBytes []byte) {
	template, err := pki.GenerateTemplate(crt)
	if err != nil {
		t.Errorf("error generating template: %v", err)
	}

	derBytes, err = x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Errorf("error signing cert: %v", err)
		t.FailNow()
	}

	pemByteBuffer := bytes.NewBuffer([]byte{})
	err = pem.Encode(pemByteBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		t.Errorf("failed to encode cert: %v", err)
		t.FailNow()
	}

	return derBytes, pemByteBuffer.Bytes()
}

func allFieldsSetCheck(expectedCA []byte) func(t *testing.T, s *caFixture, args ...interface{}) {
	return func(t *testing.T, s *caFixture, args ...interface{}) {
		resp := args[1].(*issuer.IssueResponse)

		if resp.PrivateKey == nil {
			t.Errorf("expected new private key to be generated")
		}
		if resp.Certificate == nil {
			t.Errorf("expected new certificate to be issued")
		}
		if resp.CA == nil || !reflect.DeepEqual(expectedCA, resp.CA) {
			t.Errorf("expected CA certificate to be returned")
		}
	}
}

func TestIssue(t *testing.T) {
	// Build root RSA CA
	rsaPK := generateRSAPrivateKey(t)
	rsaPKBytes := pki.EncodePKCS1PrivateKey(rsaPK)
	rootRSACrt := gen.Certificate("test-root-ca",
		gen.SetCertificateCommonName("root-ca"),
		gen.SetCertificateIsCA(true),
	)
	// generate a self signed root ca valid for 60d
	_, rsaPEMCert := generateSelfSignedCert(t, rootRSACrt, rsaPK, time.Hour*24*60)
	rootRSACASecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "root-ca-secret",
			Namespace: gen.DefaultTestNamespace,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: rsaPKBytes,
			corev1.TLSCertKey:       rsaPEMCert,
		},
	}

	// Build root ECDSA CA
	ecdsaPK := generateECDSAPrivateKey(t)
	rootECDSACrt := gen.Certificate("test-root-ca",
		gen.SetCertificateCommonName("root-ca"),
		gen.SetCertificateIsCA(true),
	)

	ecdsaPKBytes, err := pki.EncodePrivateKey(ecdsaPK, rootECDSACrt.Spec.KeyEncoding)

	if err != nil {
		t.Errorf("Error encoding private key: %v", err)
		t.FailNow()
	}
	// generate a self signed root ca valid for 60d
	_, ecdsaPEMCert := generateSelfSignedCert(t, rootECDSACrt, ecdsaPK, time.Hour*24*60)
	rootECDSACASecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "root-ca-secret",
			Namespace: gen.DefaultTestNamespace,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: ecdsaPKBytes,
			corev1.TLSCertKey:       ecdsaPEMCert,
		},
	}

	tests := map[string]caFixture{
		"sign a Certificate and generate a new RSA private key": {
			Issuer: gen.Issuer("ca-issuer",
				gen.SetIssuerCA(v1alpha1.CAIssuer{SecretName: "root-ca-secret"}),
			),
			Certificate: gen.Certificate("test-crt",
				gen.SetCertificateSecretName("crt-output"),
				gen.SetCertificateCommonName("testing-cn"),
				gen.SetCertificateKeyAlgorithm(v1alpha1.RSAKeyAlgorithm),
				gen.SetCertificateKeySize(2048),
			),
			Builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{rootRSACASecret},
				CertManagerObjects: []runtime.Object{},
			},
			CheckFn: allFieldsSetCheck(rsaPEMCert),
			Err:     false,
		},
		"sign a Certificate and generate a new ECDSA private key using RSA issuer": {
			Issuer: gen.Issuer("ca-issuer",
				gen.SetIssuerCA(v1alpha1.CAIssuer{SecretName: "root-ca-secret"}),
			),
			Certificate: gen.Certificate("test-crt",
				gen.SetCertificateSecretName("crt-output"),
				gen.SetCertificateCommonName("testing-cn"),
				gen.SetCertificateKeyAlgorithm(v1alpha1.ECDSAKeyAlgorithm),
				gen.SetCertificateKeySize(521),
			),
			Builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{rootRSACASecret},
				CertManagerObjects: []runtime.Object{},
			},
			CheckFn: allFieldsSetCheck(rsaPEMCert),
			Err:     false,
		},
		"sign a Certificate and generate a new RSA private key using ECDSA issuer": {
			Issuer: gen.Issuer("ca-issuer",
				gen.SetIssuerCA(v1alpha1.CAIssuer{SecretName: "root-ca-secret"}),
			),
			Certificate: gen.Certificate("test-crt",
				gen.SetCertificateSecretName("crt-output"),
				gen.SetCertificateCommonName("testing-cn"),
				gen.SetCertificateKeyAlgorithm(v1alpha1.RSAKeyAlgorithm),
				gen.SetCertificateKeySize(2048),
			),
			Builder: &testpkg.Builder{
				KubeObjects:        []runtime.Object{rootECDSACASecret},
				CertManagerObjects: []runtime.Object{},
			},
			CheckFn: allFieldsSetCheck(ecdsaPEMCert),
			Err:     false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if test.Builder == nil {
				test.Builder = &testpkg.Builder{}
			}
			test.Setup(t)
			certCopy := test.Certificate.DeepCopy()
			resp, err := test.CA.Issue(test.Ctx, certCopy)
			if err != nil && !test.Err {
				t.Errorf("Expected function to not error, but got: %v", err)
			}
			if err == nil && test.Err {
				t.Errorf("Expected function to get an error, but got: %v", err)
			}
			test.Finish(t, certCopy, resp, err)
		})
	}
}
