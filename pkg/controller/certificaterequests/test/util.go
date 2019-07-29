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

package test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"reflect"
	"testing"
	"time"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

func GenerateRSAPrivateKey(t *testing.T) *rsa.PrivateKey {
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err)
		t.FailNow()
	}
	return pk
}

func GenerateCSR(t *testing.T, secretKey crypto.Signer) []byte {
	asn1Subj, _ := asn1.Marshal(pkix.Name{
		CommonName: "test",
	}.ToRDNSequence())
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, secretKey)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	return csr
}

func MustNoResponse(builder *testpkg.Builder, args ...interface{}) {
	resp := args[0].(*issuer.IssueResponse)
	if resp != nil {
		builder.T.Errorf("unexpected response, exp='nil' got='%+v'", resp)
	}
}

func NoPrivateKeyFieldsSetCheck(expectedCA []byte) func(builder *testpkg.Builder, args ...interface{}) {
	return func(builder *testpkg.Builder, args ...interface{}) {
		resp := args[0].(*issuer.IssueResponse)

		if resp == nil {
			builder.T.Errorf("no response given, got=%s", resp)
			return
		}

		if len(resp.PrivateKey) > 0 {
			builder.T.Errorf("expected no new private key to be generated but got: %s",
				resp.PrivateKey)
		}

		CertificatesFieldsSetCheck(expectedCA)(builder, args...)
	}
}

func CertificatesFieldsSetCheck(expectedCA []byte) func(builder *testpkg.Builder, args ...interface{}) {
	return func(builder *testpkg.Builder, args ...interface{}) {
		resp := args[0].(*issuer.IssueResponse)

		if resp.Certificate == nil {
			builder.T.Errorf("expected new certificate to be issued")
		}
		if resp.CA == nil || !reflect.DeepEqual(expectedCA, resp.CA) {
			builder.T.Errorf("expected CA certificate to be returned")
		}
	}
}

func GenerateSelfSignedCertFromCR(t *testing.T, cr *v1alpha1.CertificateRequest, key crypto.Signer,
	duration time.Duration) (derBytes, pemBytes []byte) {
	template, err := pki.GenerateTemplateFromCertificateRequest(cr)
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
