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

package pki

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"strings"
	"testing"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/stretchr/testify/assert"
)

func generatePrivateKeyBytes(keyAlgo v1.PrivateKeyAlgorithm, keySize int) ([]byte, error) {
	cert := buildCertificateWithKeyParams(keyAlgo, keySize)
	privateKey, err := GeneratePrivateKeyForCertificate(cert)
	if err != nil {
		return nil, err
	}

	return EncodePrivateKey(privateKey, cert.Spec.PrivateKey.Encoding)
}

func generatePKCS8PrivateKey(keyAlgo v1.PrivateKeyAlgorithm, keySize int) ([]byte, error) {
	privateKey, err := GeneratePrivateKeyForCertificate(buildCertificateWithKeyParams(keyAlgo, keySize))
	if err != nil {
		return nil, err
	}
	return EncodePKCS8PrivateKey(privateKey)
}

func TestDecodePrivateKeyBytes(t *testing.T) {
	type testT struct {
		name         string
		keyBytes     []byte
		keyAlgo      v1.PrivateKeyAlgorithm
		expectErr    bool
		expectErrStr string
	}

	rsaKeyBytes, err := generatePrivateKeyBytes(v1.RSAKeyAlgorithm, MinRSAKeySize)
	if err != nil {
		t.Errorf("error generating key bytes: %s", err)
		return
	}

	pkcs8RsaKeyBytes, err := generatePKCS8PrivateKey(v1.RSAKeyAlgorithm, MinRSAKeySize)
	if err != nil {
		t.Errorf("error generating key bytes: %s", err)
		return
	}

	ecdsaKeyBytes, err := generatePrivateKeyBytes(v1.ECDSAKeyAlgorithm, 256)
	if err != nil {
		t.Errorf("error generating key bytes: %s", err)
		return
	}

	pkcs8EcdsaKeyBytes, err := generatePKCS8PrivateKey(v1.ECDSAKeyAlgorithm, 256)
	if err != nil {
		t.Errorf("error generating key bytes: %s", err)
		return
	}

	block := &pem.Block{Type: "BLAH BLAH BLAH", Bytes: []byte("blahblahblah")}
	blahKeyBytes := pem.EncodeToMemory(block)

	privateKeyBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("blahblahblah")}
	blahPrivateKeyBytes := pem.EncodeToMemory(privateKeyBlock)

	invalidKeyBytes := []byte("blah-blah-invalid")

	tests := []testT{
		{
			name:      "decode pem encoded rsa private key bytes",
			keyBytes:  rsaKeyBytes,
			keyAlgo:   v1.RSAKeyAlgorithm,
			expectErr: false,
		},
		{
			name:      "decode pkcs#8 encoded rsa private key bytes",
			keyBytes:  pkcs8RsaKeyBytes,
			keyAlgo:   v1.RSAKeyAlgorithm,
			expectErr: false,
		},
		{
			name:      "decode pem encoded ecdsa private key bytes",
			keyBytes:  ecdsaKeyBytes,
			keyAlgo:   v1.ECDSAKeyAlgorithm,
			expectErr: false,
		},
		{
			name:      "decode pkcs#8 encoded ecdsa private key bytes",
			keyBytes:  pkcs8EcdsaKeyBytes,
			keyAlgo:   v1.ECDSAKeyAlgorithm,
			expectErr: false,
		},
		{
			name:         "fail to decode unknown pem encoded key bytes",
			keyBytes:     blahKeyBytes,
			expectErr:    true,
			expectErrStr: "unknown private key type",
		},
		{
			name:         "fail to decode unknown pkcs#8 encoded key bytes",
			keyBytes:     blahPrivateKeyBytes,
			expectErr:    true,
			expectErrStr: "error parsing pkcs#8 private key: asn1: structure error:",
		},
		{
			name:         "fail to decode unknown not pem encoded key bytes",
			keyBytes:     invalidKeyBytes,
			expectErr:    true,
			expectErrStr: "error decoding private key PEM block",
		},
	}

	testFn := func(test testT) func(*testing.T) {
		return func(t *testing.T) {
			privateKey, err := DecodePrivateKeyBytes(test.keyBytes)
			if test.expectErr {
				if err == nil {
					t.Error("expected err, but got no error")
					return
				}

				if !strings.Contains(err.Error(), test.expectErrStr) {
					t.Errorf("expected err string to match: '%s', got: '%s'", test.expectErrStr, err.Error())
					return
				}
			}

			if !test.expectErr {
				if err != nil {
					t.Errorf("expected no err, but got '%q'", err)
					return
				}

				if test.keyAlgo == v1.RSAKeyAlgorithm {
					_, ok := privateKey.(*rsa.PrivateKey)
					if !ok {
						t.Errorf("expected rsa private key, but got %T", privateKey)
						return
					}
				}

				if test.keyAlgo == v1.ECDSAKeyAlgorithm {
					_, ok := privateKey.(*ecdsa.PrivateKey)
					if !ok {
						t.Errorf("expected ecdsa private key, but got %T", privateKey)
						return
					}
				}
			}
		}
	}

	for _, test := range tests {
		t.Run(test.name, testFn(test))
	}
}

func TestMustParseRDN(t *testing.T) {
	subject := "SERIALNUMBER=42, L=some-locality, ST=some-state-or-province, STREET=some-street, CN=foo-long.com, OU=FooLong, OU=Barq, OU=Baz, OU=Dept., O=Corp., C=US"
	rdnSeq, err := UnmarshalSubjectStringToRDNSequence(subject)
	if err != nil {
		t.Fatal(err)
	}

	expectedRdnSeq :=
		pkix.RDNSequence{
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.Country, Value: "US"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.Organization, Value: "Corp."},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.OrganizationalUnit, Value: "Dept."},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.OrganizationalUnit, Value: "Baz"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.OrganizationalUnit, Value: "Barq"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.OrganizationalUnit, Value: "FooLong"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.CommonName, Value: "foo-long.com"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.StreetAddress, Value: "some-street"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.Province, Value: "some-state-or-province"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.Locality, Value: "some-locality"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.SerialNumber, Value: "42"},
			},
		}

	assert.Equal(t, expectedRdnSeq, rdnSeq)
}

func TestMustKeepOrderInRawDerBytes(t *testing.T) {
	subject := "CN=foo-long.com,OU=FooLong,OU=Barq,OU=Baz,OU=Dept.,O=Corp.,C=US"
	bytes, err := ParseSubjectStringToRawDERBytes(subject)
	if err != nil {
		t.Fatal(err)
	}

	var rdnSeq pkix.RDNSequence
	_, err2 := asn1.Unmarshal(bytes, &rdnSeq)
	if err2 != nil {
		t.Fatal(err2)
	}

	t.Log(bytes)

	expectedRdnSeq :=
		pkix.RDNSequence{
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.Country, Value: "US"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.Organization, Value: "Corp."},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.OrganizationalUnit, Value: "Dept."},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.OrganizationalUnit, Value: "Baz"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.OrganizationalUnit, Value: "Barq"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.OrganizationalUnit, Value: "FooLong"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.CommonName, Value: "foo-long.com"},
			},
		}

	assert.Equal(t, expectedRdnSeq, rdnSeq)
	assert.Equal(t, subject, rdnSeq.String())
}

func TestShouldFailForHexDER(t *testing.T) {
	_, err := ParseSubjectStringToRawDERBytes("DF=#6666666666665006838820013100000746939546349182108463491821809FBFFFFFFFFF")
	if err == nil {
		t.Fatal("expected error, but got none")
	}

	assert.Contains(t, err.Error(), "failed to unmarshal hex-encoded string: asn1: syntax error: data truncated")
}
