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

package bundle

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

func TestAppendCertificatesToBundle(t *testing.T) {
	// Create certificates for use in tests
	expired := mustCreateCertificate(t, "expired", time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC))
	valid1 := mustCreateCertificate(t, "valid-1", time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC))
	valid2 := mustCreateCertificate(t, "valid-2", time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC))

	cases := []struct {
		Name       string
		Bundle     []byte
		Additional []byte
		Expected   []byte
		ExpectErr  bool
	}{
		{
			Name:       "append_to_empty_bundle",
			Bundle:     nil,
			Additional: valid1,
			Expected:   valid1,
		},
		{
			Name:       "append_to_non_empty_bundle",
			Bundle:     valid1,
			Additional: valid2,
			Expected:   joinPEM(valid1, valid2),
		},
		{
			Name:       "removes_expired_certificates",
			Bundle:     joinPEM(valid1, expired),
			Additional: valid2,
			Expected:   joinPEM(valid1, valid2),
		},
		{
			Name:       "removes_duplicate_certificates",
			Bundle:     joinPEM(valid1, valid1),
			Additional: valid2,
			Expected:   joinPEM(valid1, valid2),
		},
		{
			Name:       "does_not_append_existing_certificates",
			Bundle:     joinPEM(valid1),
			Additional: valid1,
			Expected:   joinPEM(valid1),
		},
		{
			Name:       "does_not_append_expired_certificates",
			Bundle:     joinPEM(valid1),
			Additional: expired,
			Expected:   joinPEM(valid1),
		},
	}

	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			result, err := AppendCertificatesToBundle(test.Bundle, test.Additional)

			if (err != nil) != test.ExpectErr {
				t.Fatalf("unexpected error, expected error %t, got %q", test.ExpectErr, err)
			}

			if !bytes.Equal(result, test.Expected) {
				t.Fatalf("unexpected result, expected %q, got %q", test.Expected, result)
			}
		})
	}
}

func mustCreateCertificate(t *testing.T, name string, notBefore, notAfter time.Time) []byte {
	pk, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		BasicConstraintsValid: true,
		PublicKeyAlgorithm:    x509.ECDSA,
		PublicKey:             pk.Public(),
		IsCA:                  true,
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	var (
		issuerKey  crypto.PrivateKey
		issuerCert *x509.Certificate
	)

	issuerKey = pk
	issuerCert = template

	certPEM, _, err := pki.SignCertificate(template, issuerCert, pk.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}

	return certPEM
}

func joinPEM(first []byte, rest ...[]byte) []byte {
	for _, b := range rest {
		first = append(first, b...)
	}

	return first
}
