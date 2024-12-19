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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/cmrand"
	"github.com/cert-manager/cert-manager/pkg/util"
)

func TestKeyUsagesForCertificate(t *testing.T) {
	type testT struct {
		name                string
		usages              []cmapi.KeyUsage
		isCa                bool
		expectedKeyUsage    x509.KeyUsage
		expectedExtKeyUsage []x509.ExtKeyUsage
		expectedError       bool
	}
	tests := []testT{
		{
			name:             "default",
			usages:           []cmapi.KeyUsage{},
			expectedKeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			expectedError:    false,
		},
		{
			name:             "isCa",
			usages:           []cmapi.KeyUsage{},
			isCa:             true,
			expectedKeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
			expectedError:    false,
		},
		{
			name:             "existing keyusage",
			usages:           []cmapi.KeyUsage{"crl sign"},
			expectedKeyUsage: x509.KeyUsageCRLSign,
			expectedError:    false,
		},
		{
			name:          "nonexistent keyusage error",
			usages:        []cmapi.KeyUsage{"nonexistent"},
			expectedError: true,
		},
		{
			name:             "duplicate keyusage",
			usages:           []cmapi.KeyUsage{"signing", "signing"},
			expectedKeyUsage: x509.KeyUsageDigitalSignature,
			expectedError:    false,
		},
		{
			name:                "existing extkeyusage",
			usages:              []cmapi.KeyUsage{"server auth"},
			expectedExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			expectedError:       false,
		},
		{
			name:                "duplicate extkeyusage",
			usages:              []cmapi.KeyUsage{"s/mime", "s/mime"},
			expectedExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageEmailProtection},
			expectedError:       false,
		},
	}
	testFn := func(test testT) func(*testing.T) {
		return func(t *testing.T) {
			ku, eku, err := KeyUsagesForCertificateOrCertificateRequest(test.usages, test.isCa)
			if err != nil && !test.expectedError {
				t.Errorf("got unexpected error generating cert: %q", err)
				return
			}
			if !reflect.DeepEqual(ku, test.expectedKeyUsage) {
				t.Errorf("keyUsages don't match, got %q, expected %q", ku, test.expectedKeyUsage)
				return
			}
			if !reflect.DeepEqual(eku, test.expectedExtKeyUsage) {
				t.Errorf("extKeyUsages don't match, got %q, expected %q", eku, test.expectedExtKeyUsage)
				return
			}
		}
	}
	for _, test := range tests {
		t.Run(test.name, testFn(test))
	}
}

func TestSignatureAlgorithmForCertificate(t *testing.T) {
	type testT struct {
		name            string
		keyAlgo         cmapi.PrivateKeyAlgorithm
		keySize         int
		expectErr       bool
		expectedSigAlgo x509.SignatureAlgorithm
		expectedKeyType x509.PublicKeyAlgorithm
	}

	tests := []testT{
		{
			name:      "certificate with KeyAlgorithm rsa and size 1024",
			keyAlgo:   cmapi.RSAKeyAlgorithm,
			keySize:   1024,
			expectErr: true,
		},
		{
			name:            "certificate with KeyAlgorithm rsa and no size set should default to rsa256",
			keyAlgo:         cmapi.RSAKeyAlgorithm,
			expectedSigAlgo: x509.SHA256WithRSA,
			expectedKeyType: x509.RSA,
		},
		{
			name:            "certificate with KeyAlgorithm not set",
			keyAlgo:         cmapi.PrivateKeyAlgorithm(""),
			expectedSigAlgo: x509.SHA256WithRSA,
			expectedKeyType: x509.RSA,
		},
		{
			name:            "certificate with KeyAlgorithm rsa and size 2048",
			keyAlgo:         cmapi.RSAKeyAlgorithm,
			keySize:         2048,
			expectedSigAlgo: x509.SHA256WithRSA,
			expectedKeyType: x509.RSA,
		},
		{
			name:            "certificate with KeyAlgorithm rsa and size 3072",
			keyAlgo:         cmapi.RSAKeyAlgorithm,
			keySize:         3072,
			expectedSigAlgo: x509.SHA384WithRSA,
			expectedKeyType: x509.RSA,
		},
		{
			name:            "certificate with KeyAlgorithm rsa and size 4096",
			keyAlgo:         cmapi.RSAKeyAlgorithm,
			keySize:         4096,
			expectedSigAlgo: x509.SHA512WithRSA,
			expectedKeyType: x509.RSA,
		},
		{
			name:            "certificate with ecdsa key algorithm set and no key size default to ecdsa256",
			keyAlgo:         cmapi.ECDSAKeyAlgorithm,
			expectedSigAlgo: x509.ECDSAWithSHA256,
			expectedKeyType: x509.ECDSA,
		},
		{
			name:            "certificate with KeyAlgorithm ecdsa and size 256",
			keyAlgo:         cmapi.ECDSAKeyAlgorithm,
			keySize:         256,
			expectedSigAlgo: x509.ECDSAWithSHA256,
			expectedKeyType: x509.ECDSA,
		},
		{
			name:            "certificate with KeyAlgorithm ecdsa and size 384",
			keyAlgo:         cmapi.ECDSAKeyAlgorithm,
			keySize:         384,
			expectedSigAlgo: x509.ECDSAWithSHA384,
			expectedKeyType: x509.ECDSA,
		},
		{
			name:            "certificate with KeyAlgorithm ecdsa and size 521",
			keyAlgo:         cmapi.ECDSAKeyAlgorithm,
			keySize:         521,
			expectedSigAlgo: x509.ECDSAWithSHA512,
			expectedKeyType: x509.ECDSA,
		},
		{
			name:            "certificate with KeyAlgorithm Ed25519",
			keyAlgo:         cmapi.Ed25519KeyAlgorithm,
			expectedSigAlgo: x509.PureEd25519,
			expectedKeyType: x509.Ed25519,
		},
		{
			name:      "certificate with KeyAlgorithm ecdsa and size 100",
			keyAlgo:   cmapi.ECDSAKeyAlgorithm,
			keySize:   100,
			expectErr: true,
		},
		{
			name:      "certificate with KeyAlgorithm set to unknown key algo",
			keyAlgo:   cmapi.PrivateKeyAlgorithm("blah"),
			expectErr: true,
		},
	}

	testFn := func(test testT) func(*testing.T) {
		return func(t *testing.T) {
			actualPKAlgo, actualSigAlgo, err := SignatureAlgorithm(buildCertificateWithKeyParams(test.keyAlgo, test.keySize))
			if test.expectErr && err == nil {
				t.Error("expected err, but got no error")
				return
			}

			if !test.expectErr {
				if err != nil {
					t.Errorf("expected no err, but got '%q'", err)
					return
				}

				if actualSigAlgo != test.expectedSigAlgo {
					t.Errorf("expected %q but got %q", test.expectedSigAlgo, actualSigAlgo)
					return
				}

				if actualPKAlgo != test.expectedKeyType {
					t.Errorf("expected %q but got %q", test.expectedKeyType, actualPKAlgo)
					return
				}
			}
		}
	}

	for _, test := range tests {
		t.Run(test.name, testFn(test))
	}
}

func TestRemoveDuplicates(t *testing.T) {
	type testT struct {
		input  []string
		output []string
	}
	tests := []testT{
		{
			input:  []string{"a"},
			output: []string{"a"},
		},
		{
			input:  []string{"a", "b"},
			output: []string{"a", "b"},
		},
		{
			input:  []string{"a", "a"},
			output: []string{"a"},
		},
		{
			input:  []string{"a", "b", "a", "a", "c"},
			output: []string{"a", "b", "c"},
		},
	}
	for _, test := range tests {
		actualOutput := removeDuplicates(test.input)
		if len(actualOutput) != len(test.output) ||
			!util.EqualUnsorted(test.output, actualOutput) {
			t.Errorf("returned %q for %q but expected %q", actualOutput, test.input, test.output)
			continue
		}
	}
}

func removeDuplicates(in []string) []string {
	var found []string
Outer:
	for _, i := range in {
		for _, i2 := range found {
			if i2 == i {
				continue Outer
			}
		}
		found = append(found, i)
	}
	return found
}

func OtherNameSANRawVal(expectedOID asn1.ObjectIdentifier) (asn1.RawValue, error) {
	var otherNameParam = fmt.Sprintf("tag:%d", nameTypeOtherName)

	value, err := MarshalUniversalValue(UniversalValue{
		UTF8String: "user@example.org",
	})
	if err != nil {
		return asn1.NullRawValue, err
	}

	otherNameDer, err := asn1.MarshalWithParams(OtherName{
		TypeID: expectedOID, // UPN OID
		Value: asn1.RawValue{
			Tag:        0,
			Class:      asn1.ClassContextSpecific,
			IsCompound: true,
			Bytes:      value,
		},
	}, otherNameParam)

	if err != nil {
		return asn1.NullRawValue, err
	}
	rawVal := asn1.RawValue{
		FullBytes: otherNameDer,
	}
	return rawVal, nil
}

func TestGenerateCSR(t *testing.T) {
	exampleLiteralSubject := "CN=actual-cn, OU=FooLong, OU=Bar, O=example.org"
	exampleMultiValueRDNLiteralSubject := "CN=actual-cn, OU=FooLong+OU=Bar, O=example.org"

	asn1otherNameUpnSANRawVal, err := OtherNameSANRawVal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}) // UPN OID
	if err != nil {
		t.Fatal(err)
	}

	asn1otherNamesAMAAccountNameRawVal, err := OtherNameSANRawVal(asn1.ObjectIdentifier{1, 2, 840, 113556, 1, 4, 221}) // sAMAccountName OID
	if err != nil {
		t.Fatal(err)
	}

	// 0xa0 = DigitalSignature and Encipherment usage
	asn1DefaultKeyUsage, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0xa0}, BitLength: asn1BitLength([]byte{0xa0})})
	if err != nil {
		t.Fatal(err)
	}

	// 0xa4 = DigitalSignature, Encipherment and KeyCertSign usage
	asn1KeyUsageWithCa, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0xa4}, BitLength: asn1BitLength([]byte{0xa4})})
	if err != nil {
		t.Fatal(err)
	}

	asn1ClientAuth, err := asn1.Marshal([]asn1.ObjectIdentifier{oidExtKeyUsageClientAuth})
	if err != nil {
		t.Fatal(err)
	}

	asn1ServerClientAuth, err := asn1.Marshal([]asn1.ObjectIdentifier{oidExtKeyUsageServerAuth, oidExtKeyUsageClientAuth})
	if err != nil {
		t.Fatal(err)
	}

	asn1ExtKeyUsage, err := asn1.Marshal([]asn1.ObjectIdentifier{oidExtKeyUsageIPSECEndSystem})
	if err != nil {
		t.Fatal(err)
	}

	basicConstraintsGenerator := func(t *testing.T, isCA bool) []byte {
		data, err := asn1.Marshal(struct {
			IsCA bool `asn1:"optional"`
		}{
			IsCA: isCA,
		})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

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

	literalSubectGenerator := func(t *testing.T, literal string) []byte {
		rawSubject, err := UnmarshalSubjectStringToRDNSequence(literal)
		if err != nil {
			t.Fatal(err)
		}
		asn1Subject, err := MarshalRDNSequenceToRawDERBytes(rawSubject)
		if err != nil {
			t.Fatal(err)
		}
		return asn1Subject
	}

	tests := []struct {
		name                                    string
		crt                                     *cmapi.Certificate
		want                                    *x509.CertificateRequest
		wantErr                                 bool
		literalCertificateSubjectFeatureEnabled bool
		basicConstraintsFeatureEnabled          bool
		nameConstraintsFeatureEnabled           bool
		otherNamesFeatureEnabled                bool
	}{
		{
			name: "Generate CSR from certificate with only DNS",
			crt:  &cmapi.Certificate{Spec: cmapi.CertificateSpec{DNSNames: []string{"example.org"}}},
			want: &x509.CertificateRequest{
				Version:            0,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				ExtraExtensions: []pkix.Extension{
					sansGenerator(
						t,
						[]asn1.RawValue{
							{Tag: nameTypeDNSName, Class: 2, Bytes: []byte("example.org")},
						},
						true, // SAN is critical as the Subject is empty
					),
					{
						Id:       OIDExtensionKeyUsage,
						Value:    asn1DefaultKeyUsage,
						Critical: true,
					},
				},
				RawSubject: subjectGenerator(t, pkix.Name{}),
			},
		},
		{
			name: "Generate CSR from certificate with subject and DNS",
			crt: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
				Subject:  &cmapi.X509Subject{Organizations: []string{"example inc."}},
				DNSNames: []string{"example.org"},
			}},
			want: &x509.CertificateRequest{
				Version:            0,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				ExtraExtensions: []pkix.Extension{
					sansGenerator(
						t,
						[]asn1.RawValue{
							{Tag: nameTypeDNSName, Class: 2, Bytes: []byte("example.org")},
						},
						false, // SAN is NOT critical as the Subject is not empty
					),
					{
						Id:       OIDExtensionKeyUsage,
						Value:    asn1DefaultKeyUsage,
						Critical: true,
					},
				},
				RawSubject: subjectGenerator(t, pkix.Name{Organization: []string{"example inc."}}),
			},
		},
		{
			name: "Generate CSR from certificate with only CN",
			crt:  &cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.org"}},
			want: &x509.CertificateRequest{
				Version:            0,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				ExtraExtensions: []pkix.Extension{
					{
						Id:       OIDExtensionKeyUsage,
						Value:    asn1DefaultKeyUsage,
						Critical: true,
					},
				},
				RawSubject: subjectGenerator(t, pkix.Name{CommonName: "example.org"}),
			},
		},
		{
			name: "Generate CSR from certificate with isCA set",
			crt:  &cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.org", IsCA: true}},
			want: &x509.CertificateRequest{
				Version:            0,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				ExtraExtensions: []pkix.Extension{
					{
						Id:       OIDExtensionKeyUsage,
						Value:    asn1KeyUsageWithCa,
						Critical: true,
					},
				},
				RawSubject: subjectGenerator(t, pkix.Name{CommonName: "example.org"}),
			},
		},
		{
			name: "Generate CSR from certificate with isCA not set and with UseCertificateRequestBasicConstraints flag enabled",
			crt:  &cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.org"}},
			want: &x509.CertificateRequest{
				Version:            0,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				ExtraExtensions: []pkix.Extension{
					{
						Id:       OIDExtensionKeyUsage,
						Value:    asn1DefaultKeyUsage,
						Critical: true,
					},
					{
						Id:       OIDExtensionBasicConstraints,
						Value:    basicConstraintsGenerator(t, false),
						Critical: true,
					},
				},
				RawSubject: subjectGenerator(t, pkix.Name{CommonName: "example.org"}),
			},
			basicConstraintsFeatureEnabled: true,
		},
		{
			name: "Generate CSR from certificate with isCA set and with UseCertificateRequestBasicConstraints flag enabled",
			crt:  &cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.org", IsCA: true}},
			want: &x509.CertificateRequest{
				Version:            0,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				ExtraExtensions: []pkix.Extension{
					{
						Id:       OIDExtensionKeyUsage,
						Value:    asn1KeyUsageWithCa,
						Critical: true,
					},
					{
						Id:       OIDExtensionBasicConstraints,
						Value:    basicConstraintsGenerator(t, true),
						Critical: true,
					},
				},
				RawSubject: subjectGenerator(t, pkix.Name{CommonName: "example.org"}),
			},
			basicConstraintsFeatureEnabled: true,
		},
		{
			name: "Generate CSR from certificate with extended key usages",
			crt:  &cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.org", Usages: []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageIPsecEndSystem}}},
			want: &x509.CertificateRequest{
				Version:            0,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				ExtraExtensions: []pkix.Extension{
					{
						Id:       OIDExtensionKeyUsage,
						Value:    asn1DefaultKeyUsage,
						Critical: true,
					},
					{
						Id:    OIDExtensionExtendedKeyUsage,
						Value: asn1ExtKeyUsage,
					},
				},
				RawSubject: subjectGenerator(t, pkix.Name{CommonName: "example.org"}),
			},
		},
		{
			name: "Generate CSR from certificate with a single otherNameSAN set to an oid (UPN)", // only a shallow validation is expected
			crt: &cmapi.Certificate{Spec: cmapi.CertificateSpec{OtherNames: []cmapi.OtherName{
				{
					OID:       "1.3.6.1.4.1.311.20.2.3",
					UTF8Value: "user@example.org",
				},
			}}},
			want: &x509.CertificateRequest{
				Version:            0,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				ExtraExtensions: []pkix.Extension{
					sansGenerator(
						t,
						[]asn1.RawValue{asn1otherNameUpnSANRawVal},
						true,
					),
					{
						Id:       OIDExtensionKeyUsage,
						Value:    asn1DefaultKeyUsage,
						Critical: true,
					},
				},
				RawSubject: subjectGenerator(t, pkix.Name{}),
			},
			otherNamesFeatureEnabled: true,
		},
		{
			name: "Generate CSR from certificate with multiple valid otherName oids and emailSANs set",
			crt: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
				EmailAddresses: []string{"user@example.org", "alt-email@example.org"},
				OtherNames: []cmapi.OtherName{
					{
						OID:       "1.3.6.1.4.1.311.20.2.3",
						UTF8Value: "user@example.org",
					},
					{
						OID:       "1.2.840.113556.1.4.221",
						UTF8Value: "user@example.org",
					},
				}}},
			want: &x509.CertificateRequest{
				Version:            0,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				ExtraExtensions: []pkix.Extension{
					sansGenerator(
						t,
						[]asn1.RawValue{
							{Tag: nameTypeRFC822Name, Class: 2, Bytes: []byte("user@example.org")},
							{Tag: nameTypeRFC822Name, Class: 2, Bytes: []byte("alt-email@example.org")},
							asn1otherNameUpnSANRawVal,
							asn1otherNamesAMAAccountNameRawVal,
						},
						true,
					),
					{
						Id:       OIDExtensionKeyUsage,
						Value:    asn1DefaultKeyUsage,
						Critical: true,
					},
				},
				RawSubject: subjectGenerator(t, pkix.Name{}),
			},
			otherNamesFeatureEnabled: true,
		},
		{
			name: "Generate CSR from certificate with malformed otherName oid type",
			crt: &cmapi.Certificate{Spec: cmapi.CertificateSpec{OtherNames: []cmapi.OtherName{
				{
					OID:       "NOTANOID@garbage",
					UTF8Value: "user@example.org",
				},
			}}},
			wantErr: true,
		},
		{
			name: "Generate CSR from certificate with double signing key usages",
			crt:  &cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.org", Usages: []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageSigning}}},
			want: &x509.CertificateRequest{
				Version:            0,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				ExtraExtensions: []pkix.Extension{
					{
						Id:       OIDExtensionKeyUsage,
						Value:    asn1DefaultKeyUsage,
						Critical: true,
					},
				},
				RawSubject: subjectGenerator(t, pkix.Name{CommonName: "example.org"}),
			},
		},
		{
			name:    "Error on generating CSR from certificate with no subject",
			crt:     &cmapi.Certificate{Spec: cmapi.CertificateSpec{}},
			wantErr: true,
		},
		{
			name: "Generate CSR from certificate with literal subject honouring the exact order",
			crt:  &cmapi.Certificate{Spec: cmapi.CertificateSpec{LiteralSubject: exampleLiteralSubject}},
			want: &x509.CertificateRequest{
				Version:            0,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				ExtraExtensions: []pkix.Extension{
					{
						Id:       OIDExtensionKeyUsage,
						Value:    asn1DefaultKeyUsage,
						Critical: true,
					},
				},
				RawSubject: literalSubectGenerator(t, exampleLiteralSubject),
			},
			literalCertificateSubjectFeatureEnabled: true,
		},
		{
			name: "Generate CSR from certificate with literal multi value subject honouring the exact order",
			crt:  &cmapi.Certificate{Spec: cmapi.CertificateSpec{LiteralSubject: exampleMultiValueRDNLiteralSubject}},
			want: &x509.CertificateRequest{
				Version:            0,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				ExtraExtensions: []pkix.Extension{
					{
						Id:       OIDExtensionKeyUsage,
						Value:    asn1DefaultKeyUsage,
						Critical: true,
					},
				},
				RawSubject: literalSubectGenerator(t, exampleMultiValueRDNLiteralSubject),
			},
			literalCertificateSubjectFeatureEnabled: true,
		},
		{
			name:                                    "Error on generating CSR from certificate without CommonName in LiteralSubject, uri names, email address, ip addresses or otherName set",
			crt:                                     &cmapi.Certificate{Spec: cmapi.CertificateSpec{LiteralSubject: "O=EmptyOrg"}},
			wantErr:                                 true,
			literalCertificateSubjectFeatureEnabled: true,
		},
		{
			name: "KeyUsages and ExtendedKeyUsages: no usages set",
			crt:  &cmapi.Certificate{Spec: cmapi.CertificateSpec{DNSNames: []string{"example.org"}}},
			want: &x509.CertificateRequest{
				Version:            0,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				ExtraExtensions: []pkix.Extension{
					sansGenerator(
						t,
						[]asn1.RawValue{
							{Tag: nameTypeDNSName, Class: 2, Bytes: []byte("example.org")},
						},
						true,
					),
					{
						Id:       OIDExtensionKeyUsage,
						Value:    asn1DefaultKeyUsage,
						Critical: true,
					},
				},
				RawSubject: subjectGenerator(t, pkix.Name{}),
			},
			wantErr: false,
		},
		{
			name: "KeyUsages and ExtendedKeyUsages: client auth extended usage set",
			crt: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					DNSNames: []string{"example.org"},
					Usages:   []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageClientAuth},
				},
			},
			want: &x509.CertificateRequest{
				Version:            0,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				ExtraExtensions: []pkix.Extension{
					sansGenerator(
						t,
						[]asn1.RawValue{
							{Tag: nameTypeDNSName, Class: 2, Bytes: []byte("example.org")},
						},
						true,
					),
					{
						Id:       OIDExtensionKeyUsage,
						Value:    asn1DefaultKeyUsage,
						Critical: true,
					},
					{
						Id:    OIDExtensionExtendedKeyUsage,
						Value: asn1ClientAuth,
					},
				},
				RawSubject: subjectGenerator(t, pkix.Name{}),
			},
			wantErr: false,
		},
		{
			name: "KeyUsages and ExtendedKeyUsages: server + client auth extended usage set",
			crt: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					DNSNames: []string{"example.org"},
					Usages:   []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageServerAuth, cmapi.UsageClientAuth},
				},
			},
			want: &x509.CertificateRequest{
				Version:            0,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				ExtraExtensions: []pkix.Extension{
					sansGenerator(
						t,
						[]asn1.RawValue{
							{Tag: nameTypeDNSName, Class: 2, Bytes: []byte("example.org")},
						},
						true,
					),
					{
						Id:       OIDExtensionKeyUsage,
						Value:    asn1DefaultKeyUsage,
						Critical: true,
					},
					{
						Id:    OIDExtensionExtendedKeyUsage,
						Value: asn1ServerClientAuth,
					},
				},
				RawSubject: subjectGenerator(t, pkix.Name{}),
			},
			wantErr: false,
		},
		{
			name: "Generate CSR from certificate with NameConstraints flag enabled",
			crt: &cmapi.Certificate{Spec: cmapi.CertificateSpec{
				CommonName: "example.org",
				IsCA:       true,
				NameConstraints: &cmapi.NameConstraints{
					Critical: true,
					Permitted: &cmapi.NameConstraintItem{
						DNSDomains:     []string{"example.org"},
						IPRanges:       []string{"10.10.0.0/16"},
						EmailAddresses: []string{"email@email.org"},
					},
					Excluded: &cmapi.NameConstraintItem{
						IPRanges: []string{"10.10.0.0/24"},
					},
				},
			}},
			want: &x509.CertificateRequest{
				Version:            0,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				ExtraExtensions: []pkix.Extension{
					{
						Id:       OIDExtensionKeyUsage,
						Value:    asn1KeyUsageWithCa,
						Critical: true,
					},
					{
						Id:       OIDExtensionNameConstraints,
						Value:    []byte{0x30, 0x3e, 0xa0, 0x2e, 0x30, 0xd, 0x82, 0xb, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6f, 0x72, 0x67, 0x30, 0xa, 0x87, 0x8, 0xa, 0xa, 0x0, 0x0, 0xff, 0xff, 0x0, 0x0, 0x30, 0x11, 0x81, 0xf, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x40, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x6f, 0x72, 0x67, 0xa1, 0xc, 0x30, 0xa, 0x87, 0x8, 0xa, 0xa, 0x0, 0x0, 0xff, 0xff, 0xff, 0x0},
						Critical: true,
					},
				},
				RawSubject: subjectGenerator(t, pkix.Name{CommonName: "example.org"}),
			},
			nameConstraintsFeatureEnabled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateCSR(
				tt.crt,
				WithEncodeBasicConstraintsInRequest(tt.basicConstraintsFeatureEnabled),
				WithNameConstraints(tt.nameConstraintsFeatureEnabled),
				WithOtherNames(tt.otherNamesFeatureEnabled),
				WithUseLiteralSubject(tt.literalCertificateSubjectFeatureEnabled),
			)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateCSR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateCSR() got = %v, want %v", got, tt.want)
				return
			}

			// TODO find a better way around the nil check
			if got != nil {
				// also check CSR generates valid certificate
				pk, err := GenerateRSAPrivateKey(2048)
				if err != nil {
					t.Fatal(err)
				}

				csrDER, err := EncodeCSR(got, pk)
				if err != nil {
					t.Fatal(err)
				}

				_, err = x509.ParseCertificateRequest(csrDER)
				if err != nil {
					t.Errorf("Failed to parse generated certificate %s, Der: %v", err.Error(), csrDER)
				}
			}
		})
	}
}

func TestSignCSRTemplate(t *testing.T) {
	// We want to test the behavior of SignCSRTemplate in various contexts;
	// for that, we construct a chain of four certificates:
	// a root CA, two intermediate CA, and a leaf certificate.

	mustCreatePair := func(issuerCert *x509.Certificate, issuerPK crypto.Signer, name string, isCA bool, nameConstraints *NameConstraints) ([]byte, *x509.Certificate, *x509.Certificate, crypto.Signer) {
		pk, err := GenerateECPrivateKey(256)
		require.NoError(t, err)
		var permittedIPRanges []*net.IPNet
		if nameConstraints != nil {
			permittedIPRanges = nameConstraints.PermittedIPRanges
		}
		tmpl := &x509.Certificate{
			Version:               3,
			BasicConstraintsValid: true,
			SerialNumber:          big.NewInt(0),
			Subject: pkix.Name{
				CommonName: name,
			},
			PublicKeyAlgorithm: x509.ECDSA,
			NotBefore:          time.Now(),
			NotAfter:           time.Now().Add(time.Minute),
			KeyUsage:           x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			PublicKey:          pk.Public(),
			IsCA:               isCA,
			PermittedIPRanges:  permittedIPRanges,
		}

		if isCA {
			tmpl.KeyUsage |= x509.KeyUsageCertSign
		}

		if issuerCert == nil {
			issuerCert = tmpl
		}
		if issuerPK == nil {
			issuerPK = pk
		}

		pem, cert, err := SignCertificate(tmpl, issuerCert, tmpl.PublicKey, issuerPK)
		require.NoError(t, err)
		return pem, cert, tmpl, pk
	}

	rootPEM, rootCert, rootTmpl, rootPK := mustCreatePair(nil, nil, "root", true, nil)
	int1PEM, int1Cert, int1Tmpl, int1PK := mustCreatePair(rootCert, rootPK, "int1", true, nil)
	int2PEM, int2Cert, int2Tmpl, int2PK := mustCreatePair(int1Cert, int1PK, "int2", true, nil)
	leafPEM, _, leafTmpl, _ := mustCreatePair(int2Cert, int2PK, "leaf", false, nil)

	// vars for testing name constraints
	_, permittedIPNet, _ := net.ParseCIDR("10.10.0.0/16")
	_, ncRootCert, _, ncRootPK := mustCreatePair(nil, nil, "ncroot", true, &NameConstraints{PermittedIPRanges: []*net.IPNet{permittedIPNet}})
	_, _, ncLeafTmpl, _ := mustCreatePair(ncRootCert, ncRootPK, "ncleaf", false, nil)
	ncLeafTmpl.IPAddresses = []net.IP{net.ParseIP("10.20.0.5")}

	tests := map[string]struct {
		caCerts           []*x509.Certificate
		caKey             crypto.Signer
		template          *x509.Certificate
		expectedCertPem   []byte
		expectedCaCertPem []byte
		wantErr           bool
	}{
		"Sign intermediate 1 template": {
			caCerts:           []*x509.Certificate{rootCert},
			caKey:             rootPK,
			template:          int1Tmpl,
			expectedCertPem:   int1PEM,
			expectedCaCertPem: rootPEM,
			wantErr:           false,
		},
		"Sign intermediate 2 template": {
			caCerts:           []*x509.Certificate{int1Cert, rootCert},
			caKey:             int1PK,
			template:          int2Tmpl,
			expectedCertPem:   append(int2PEM, int1PEM...),
			expectedCaCertPem: rootPEM,
			wantErr:           false,
		},
		"Sign leaf template": {
			caCerts:           []*x509.Certificate{int2Cert, int1Cert, rootCert},
			caKey:             int2PK,
			template:          leafTmpl,
			expectedCertPem:   append(append(leafPEM, int1PEM...), int2PEM...),
			expectedCaCertPem: rootPEM,
			wantErr:           false,
		},
		"Sign leaf template no root": {
			caCerts:           []*x509.Certificate{int2Cert, int1Cert},
			caKey:             int2PK,
			template:          leafTmpl,
			expectedCertPem:   append(leafPEM, int2PEM...),
			expectedCaCertPem: int1PEM,
			wantErr:           false,
		},
		"Error on no CA": {
			caKey:    rootPK,
			template: rootTmpl,
			wantErr:  true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			actualBundle, err := SignCSRTemplate(test.caCerts, test.caKey, test.template)
			if (err != nil) != test.wantErr {
				t.Errorf("TestSignCSRTemplate() error = %v, wantErr %v", err, test.wantErr)
				return
			}

			if !bytes.Equal(test.expectedCertPem, actualBundle.ChainPEM) {
				// To help us identify where the mismatch is, we decode turn the
				// into strings and do a textual diff.
				expected, _ := DecodeX509CertificateBytes(test.expectedCertPem)
				actual, _ := DecodeX509CertificateBytes(actualBundle.ChainPEM)

				assert.Equal(t, expected.Subject.String(), actual.Subject.String())
			}

			if !bytes.Equal(test.expectedCaCertPem, actualBundle.CAPEM) {
				// To help us identify where the mismatch is, we decode turn the
				// into strings and do a textual diff.
				expected, _ := DecodeX509CertificateBytes(test.expectedCaCertPem)
				actual, _ := DecodeX509CertificateBytes(actualBundle.CAPEM)

				assert.Equal(t, expected.Subject.String(), actual.Subject.String())
			}
		})
	}
}

func TestEncodeX509Chain(t *testing.T) {
	root := mustCreateBundle(t, nil, "root")
	intA1 := mustCreateBundle(t, root, "intA-1")
	intA2 := mustCreateBundle(t, intA1, "intA-2")
	leafA1 := mustCreateBundle(t, intA1, "leaf-a1")
	leafA2 := mustCreateBundle(t, intA2, "leaf-a2")
	leafInterCN := mustCreateBundle(t, intA1, intA1.cert.Subject.CommonName)

	tests := map[string]struct {
		inputCerts []*x509.Certificate
		expChain   []byte
		expErr     bool
	}{
		"simple 3 cert chain should be encoded in the same order as passed, with no root": {
			inputCerts: []*x509.Certificate{root.cert, intA1.cert, leafA1.cert},
			expChain:   joinPEM(intA1.pem, leafA1.pem),
			expErr:     false,
		},
		"simple 4 cert chain should be encoded in the same order as passed, with no root": {
			inputCerts: []*x509.Certificate{root.cert, intA1.cert, intA2.cert, leafA2.cert},
			expChain:   joinPEM(intA1.pem, intA2.pem, leafA2.pem),
			expErr:     false,
		},
		"3 cert chain with no leaf be encoded in the same order as passed, with no root": {
			inputCerts: []*x509.Certificate{root.cert, intA1.cert, intA2.cert},
			expChain:   joinPEM(intA1.pem, intA2.pem),
			expErr:     false,
		},
		"chain with a non-root cert where issuer matches subject should include that cert but not root": {
			// see https://github.com/cert-manager/cert-manager/issues/4142#issuecomment-884248923
			inputCerts: []*x509.Certificate{root.cert, intA1.cert, leafInterCN.cert},
			expChain:   joinPEM(intA1.pem, leafInterCN.pem),
			expErr:     false,
		},
		"empty input chain should result in no output and no error": {
			inputCerts: []*x509.Certificate{},
			expChain:   []byte(""),
			expErr:     false,
		},
		"chain with just a root should result in no output and no error": {
			inputCerts: []*x509.Certificate{root.cert},
			expChain:   []byte(""),
			expErr:     false,
		},
		"chain with just a leaf should result in just the leaf": {
			inputCerts: []*x509.Certificate{leafA1.cert},
			expChain:   leafA1.pem,
			expErr:     false,
		},
		"nil certs are ignored": {
			inputCerts: []*x509.Certificate{leafA1.cert, nil},
			expChain:   leafA1.pem,
			expErr:     false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			chainOut, err := EncodeX509Chain(test.inputCerts)

			if (err != nil) != test.expErr {
				t.Errorf("unexpected error, exp=%t got=%v",
					test.expErr, err)
			}

			if !reflect.DeepEqual(chainOut, test.expChain) {
				t.Errorf("unexpected output from EncodeX509Chain, exp=%+s got=%+s",
					test.expChain, chainOut)
			}
		})
	}
}

func rsaKey(t *testing.T, size int) crypto.Signer {
	t.Helper()

	var key crypto.Signer
	var err error

	if size < MinRSAKeySize {
		// Special case; GenerateRSAPrivateKey doesn't support insecure keys but we want one for
		// testing in this case.
		key, err = rsa.GenerateKey(cmrand.Reader, size)
	} else {
		key, err = GenerateRSAPrivateKey(size)
	}

	if err != nil {
		t.Fatalf("failed to generate RSA key with size %d: %s", size, err)
	}

	return key
}

func ecdsaKey(t *testing.T, size int) crypto.Signer {
	t.Helper()

	var key crypto.Signer
	var err error

	if size == 224 {
		// Special case; we don't support P224 in our keygen (because it's not widely used in
		// web PKI).
		// So we have to manually generate a curve here with different logic
		key, err = ecdsa.GenerateKey(elliptic.P224(), cmrand.Reader)
	} else {
		key, err = GenerateECPrivateKey(size)
	}

	if err != nil {
		t.Fatalf("failed to generate ECDSA key with curve %d: %s", size, err)
	}

	return key
}

func ed25519Key(t *testing.T) crypto.Signer {
	t.Helper()

	priv, err := GenerateEd25519PrivateKey()
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %s", err)
	}

	return priv
}

func Test_SignCertificate_Signatures(t *testing.T) {
	specs := map[string]struct {
		SignerKey                  crypto.Signer
		ExpectedSignatureAlgorithm x509.SignatureAlgorithm
		ExpectErr                  bool
	}{
		"RSA 2048": {
			SignerKey:                  rsaKey(t, 2048),
			ExpectedSignatureAlgorithm: x509.SHA256WithRSA,
		},
		"RSA 3072": {
			SignerKey:                  rsaKey(t, 3072),
			ExpectedSignatureAlgorithm: x509.SHA384WithRSA,
		},
		"RSA 4096": {
			SignerKey:                  rsaKey(t, 4096),
			ExpectedSignatureAlgorithm: x509.SHA512WithRSA,
		},
		"RSA 8192": {
			SignerKey:                  rsaKey(t, 8192),
			ExpectedSignatureAlgorithm: x509.SHA512WithRSA,
		},
		"RSA 1024 should error": {
			SignerKey:                  rsaKey(t, 1024),
			ExpectedSignatureAlgorithm: x509.UnknownSignatureAlgorithm,
			ExpectErr:                  true,
		},
		"ECDSA P-224 should error": {
			SignerKey:                  ecdsaKey(t, 224),
			ExpectedSignatureAlgorithm: x509.UnknownSignatureAlgorithm,
			ExpectErr:                  true,
		},
		"ECDSA P-256": {
			SignerKey:                  ecdsaKey(t, 256),
			ExpectedSignatureAlgorithm: x509.ECDSAWithSHA256,
		},
		"ECDSA P-384": {
			SignerKey:                  ecdsaKey(t, 384),
			ExpectedSignatureAlgorithm: x509.ECDSAWithSHA384,
		},
		"ECDSA P-521": {
			SignerKey:                  ecdsaKey(t, 521),
			ExpectedSignatureAlgorithm: x509.ECDSAWithSHA512,
		},
		"Ed25519": {
			SignerKey:                  ed25519Key(t),
			ExpectedSignatureAlgorithm: x509.PureEd25519,
		},
	}

	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			signerKey := spec.SignerKey
			pub := signerKey.Public()

			serialNumber, err := cmrand.SerialNumber()
			if err != nil {
				t.Fatalf("failed to generate serial number for certificate: %s", err)
			}

			tmpl := &x509.Certificate{
				SerialNumber: serialNumber,

				PublicKey: pub,
				Subject:   pkix.Name{CommonName: "abc123"},

				DNSNames: []string{"example.com"},
			}

			leafPriv := ed25519Key(t)
			leafPub := leafPriv.Public()

			_, cert, err := SignCertificate(tmpl, tmpl, leafPub, signerKey)
			if (err != nil) != spec.ExpectErr {
				t.Errorf("failed to SignCertificate: %s", err)
			}

			if spec.ExpectErr {
				return
			}

			if cert.SignatureAlgorithm != spec.ExpectedSignatureAlgorithm {
				t.Errorf("wanted sigalg=%v but got %v", spec.ExpectedSignatureAlgorithm, cert.SignatureAlgorithm)
				return
			}
		})
	}
}
