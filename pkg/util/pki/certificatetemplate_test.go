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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"reflect"
	"testing"
)

func TestCertificateTemplateFromCSR(t *testing.T) {
	subjectGenerator := func(t *testing.T, name pkix.Name) []byte {
		data, err := MarshalRDNSequenceToRawDERBytes(name.ToRDNSequence())
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	sansGenerator := func(t *testing.T, generalNames []asn1.RawValue, critical bool) pkix.Extension {
		val, err := asn1.Marshal(generalNames)
		if err != nil {
			t.Fatal(err)
		}

		return pkix.Extension{
			Id:       oidExtensionSubjectAltName,
			Critical: critical,
			Value:    val,
		}
	}

	testCases := []struct {
		name     string
		csr      *x509.CertificateRequest
		expected *x509.Certificate
	}{
		{
			name: "should copy subject",
			csr: &x509.CertificateRequest{
				Subject: pkix.Name{
					Country:            []string{"US"},
					Organization:       []string{"cert-manager"},
					OrganizationalUnit: []string{"test"},
					CommonName:         "test",
				},
			},
			expected: &x509.Certificate{
				Version: 3,
				Subject: pkix.Name{
					Country:            []string{"US"},
					Organization:       []string{"cert-manager"},
					OrganizationalUnit: []string{"test"},
					CommonName:         "test",
				},
			},
		},
		{
			name: "should copy raw subject + SANs",
			csr: &x509.CertificateRequest{
				RawSubject: subjectGenerator(t, pkix.Name{
					Country:            []string{"US"},
					Organization:       []string{"cert-manager"},
					OrganizationalUnit: []string{"test"},
				}),
				DNSNames: []string{"test.example.com"},
			},
			expected: &x509.Certificate{
				Version: 3,
				RawSubject: subjectGenerator(t, pkix.Name{
					Country:            []string{"US"},
					Organization:       []string{"cert-manager"},
					OrganizationalUnit: []string{"test"},
				}),
				DNSNames: []string{"test.example.com"},
			},
		},
		{
			name: "should ignore unknown extensions",
			csr: &x509.CertificateRequest{
				ExtraExtensions: []pkix.Extension{
					{
						Id:    []int{1, 2, 3},
						Value: []byte("test"),
					},
				},
			},
			expected: &x509.Certificate{
				Version: 3,
			},
		},
		{
			name: "should copy SANs and not fix critical flag subject is set",
			csr: &x509.CertificateRequest{
				Subject: pkix.Name{
					Country:      []string{"US"},
					Organization: []string{"cert-manager"},
				},
				ExtraExtensions: []pkix.Extension{
					sansGenerator(t, []asn1.RawValue{
						{Tag: 2, Class: 2, Bytes: []byte("test.example.com")},
					}, false),
				},
			},
			expected: &x509.Certificate{
				Version: 3,
				Subject: pkix.Name{
					Country:      []string{"US"},
					Organization: []string{"cert-manager"},
				},
				ExtraExtensions: []pkix.Extension{
					sansGenerator(t, []asn1.RawValue{
						{Tag: 2, Class: 2, Bytes: []byte("test.example.com")},
					}, false),
				},
			},
		},
		{
			name: "should copy SANs and fix its critical flag",
			csr: &x509.CertificateRequest{
				ExtraExtensions: []pkix.Extension{
					sansGenerator(t, []asn1.RawValue{
						{Tag: 2, Class: 2, Bytes: []byte("test.example.com")},
					}, false),
				},
			},
			expected: &x509.Certificate{
				Version: 3,
				ExtraExtensions: []pkix.Extension{
					sansGenerator(t, []asn1.RawValue{
						{Tag: 2, Class: 2, Bytes: []byte("test.example.com")},
					}, true),
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := CertificateTemplateFromCSR(tc.csr)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if result.SerialNumber == nil {
				t.Errorf("expected serial number to be set")
			}

			// Set serial number to nil to avoid comparing it
			result.SerialNumber = nil

			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("unexpected result: %v", result)
			}
		})
	}
}
