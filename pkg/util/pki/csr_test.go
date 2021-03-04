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

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	v1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jetstack/cert-manager/pkg/util"
)

func buildCertificate(cn string, dnsNames ...string) *cmapi.Certificate {
	return &cmapi.Certificate{
		Spec: cmapi.CertificateSpec{
			CommonName: cn,
			DNSNames:   dnsNames,
		},
	}
}

func TestBuildUsages(t *testing.T) {
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
			ku, eku, err := BuildKeyUsages(test.usages, test.isCa)
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

func TestCommonNameForCertificate(t *testing.T) {
	type testT struct {
		name        string
		crtCN       string
		crtDNSNames []string
		expectedCN  string
	}
	tests := []testT{
		{
			name:       "certificate with CommonName set",
			crtCN:      "test",
			expectedCN: "test",
		},
		{
			name:        "certificate with one DNS name set",
			crtDNSNames: []string{"dnsname"},
			expectedCN:  "",
		},
		{
			name:        "certificate with both common name and dnsName set",
			crtCN:       "cn",
			crtDNSNames: []string{"dnsname"},
			expectedCN:  "cn",
		},
		{
			name:        "certificate with multiple dns names set",
			crtDNSNames: []string{"dnsname1", "dnsname2"},
			expectedCN:  "",
		},
	}
	testFn := func(test testT) func(*testing.T) {
		return func(t *testing.T) {
			actualCN := buildCertificate(test.crtCN, test.crtDNSNames...).Spec.CommonName
			if actualCN != test.expectedCN {
				t.Errorf("expected %q but got %q", test.expectedCN, actualCN)
				return
			}
		}
	}
	for _, test := range tests {
		t.Run(test.name, testFn(test))
	}
}

func TestDNSNamesForCertificate(t *testing.T) {
	type testT struct {
		name           string
		crtCN          string
		crtDNSNames    []string
		expectDNSNames []string
	}
	tests := []testT{
		{
			name:           "certificate with CommonName set",
			crtCN:          "test",
			expectDNSNames: []string{},
		},
		{
			name:           "certificate with one DNS name set",
			crtDNSNames:    []string{"dnsname"},
			expectDNSNames: []string{"dnsname"},
		},
		{
			name:           "certificate with both common name and dnsName set",
			crtCN:          "cn",
			crtDNSNames:    []string{"dnsname"},
			expectDNSNames: []string{"dnsname"},
		},
		{
			name:           "certificate with multiple dns names set",
			crtDNSNames:    []string{"dnsname1", "dnsname2"},
			expectDNSNames: []string{"dnsname1", "dnsname2"},
		},
		{
			name:           "certificate with dnsName[0] set to equal common name",
			crtCN:          "cn",
			crtDNSNames:    []string{"cn", "dnsname"},
			expectDNSNames: []string{"cn", "dnsname"},
		},
		{
			name:           "certificate with a dnsName equal to cn",
			crtCN:          "cn",
			crtDNSNames:    []string{"dnsname", "cn"},
			expectDNSNames: []string{"dnsname", "cn"},
		},
	}
	testFn := func(test testT) func(*testing.T) {
		return func(t *testing.T) {
			actualDNSNames := buildCertificate(test.crtCN, test.crtDNSNames...).Spec.DNSNames
			if len(actualDNSNames) != len(test.expectDNSNames) {
				t.Errorf("expected %q but got %q", test.expectDNSNames, actualDNSNames)
				return
			}
			for i, actual := range actualDNSNames {
				if test.expectDNSNames[i] != actual {
					t.Errorf("expected %q but got %q", test.expectDNSNames, actualDNSNames)
					return
				}
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

func TestGenerateCSR(t *testing.T) {
	// 0xa0 = DigitalSignature and Encipherment usage
	asn1KeyUsage, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0xa0}, BitLength: asn1BitLength([]byte{0xa0})})
	if err != nil {
		t.Fatal(err)
	}
	defaultExtraExtensions := []pkix.Extension{
		{
			Id:    OIDExtensionKeyUsage,
			Value: asn1KeyUsage,
		},
	}

	asn1ExtKeyUsage, err := asn1.Marshal([]asn1.ObjectIdentifier{oidExtKeyUsageIPSECEndSystem})
	if err != nil {
		t.Fatal(err)
	}
	ipsecExtraExtensions := []pkix.Extension{
		{
			Id:    OIDExtensionKeyUsage,
			Value: asn1KeyUsage,
		},
		{
			Id:    OIDExtensionExtendedKeyUsage,
			Value: asn1ExtKeyUsage,
		},
	}

	tests := []struct {
		name    string
		crt     *cmapi.Certificate
		want    *x509.CertificateRequest
		wantErr bool
	}{
		{
			name: "Generate CSR from certificate with only DNS",
			crt:  &cmapi.Certificate{Spec: cmapi.CertificateSpec{DNSNames: []string{"example.org"}}},
			want: &x509.CertificateRequest{Version: 3,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				DNSNames:           []string{"example.org"},
				ExtraExtensions:    defaultExtraExtensions,
			},
		},
		{
			name: "Generate CSR from certificate with only CN",
			crt:  &cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.org"}},
			want: &x509.CertificateRequest{Version: 3,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				Subject:            pkix.Name{CommonName: "example.org"},
				ExtraExtensions:    defaultExtraExtensions,
			},
		},
		{
			name: "Generate CSR from certificate with extended key usages",
			crt:  &cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.org", Usages: []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageIPsecEndSystem}}},
			want: &x509.CertificateRequest{Version: 3,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				Subject:            pkix.Name{CommonName: "example.org"},
				ExtraExtensions:    ipsecExtraExtensions,
			},
		},
		{
			name: "Generate CSR from certificate with double signing key usages",
			crt:  &cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.org", Usages: []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageSigning}}},
			want: &x509.CertificateRequest{Version: 3,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				Subject:            pkix.Name{CommonName: "example.org"},
				ExtraExtensions:    defaultExtraExtensions,
			},
		},
		{
			name:    "Error on generating CSR from certificate with no subject",
			crt:     &cmapi.Certificate{Spec: cmapi.CertificateSpec{}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateCSR(tt.crt)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateCSR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateCSR() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_buildKeyUsagesExtensionsForCertificate(t *testing.T) {
	// 0xa0 = DigitalSignature and Encipherment usage
	asn1DefaultKeyUsage, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0xa0}, BitLength: asn1BitLength([]byte{0xa0})})
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

	tests := []struct {
		name    string
		crt     *v1.Certificate
		want    []pkix.Extension
		wantErr bool
	}{
		{
			name: "Test no usages set",
			crt:  &v1.Certificate{},
			want: []pkix.Extension{
				{
					Id:    OIDExtensionKeyUsage,
					Value: asn1DefaultKeyUsage,
				},
			},
			wantErr: false,
		},
		{
			name: "Test client auth extended usage set",
			crt: &v1.Certificate{
				Spec: v1.CertificateSpec{
					Usages: []v1.KeyUsage{v1.UsageDigitalSignature, v1.UsageKeyEncipherment, v1.UsageClientAuth},
				},
			},
			want: []pkix.Extension{
				{
					Id:    OIDExtensionKeyUsage,
					Value: asn1DefaultKeyUsage,
				},
				{
					Id:    OIDExtensionExtendedKeyUsage,
					Value: asn1ClientAuth,
				},
			},
			wantErr: false,
		},
		{
			name: "Test server + client auth extended usage set",
			crt: &v1.Certificate{
				Spec: v1.CertificateSpec{
					Usages: []v1.KeyUsage{v1.UsageDigitalSignature, v1.UsageKeyEncipherment, v1.UsageServerAuth, v1.UsageClientAuth},
				},
			},
			want: []pkix.Extension{
				{
					Id:    OIDExtensionKeyUsage,
					Value: asn1DefaultKeyUsage,
				},
				{
					Id:    OIDExtensionExtendedKeyUsage,
					Value: asn1ServerClientAuth,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildKeyUsagesExtensionsForCertificate(tt.crt)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildKeyUsagesExtensionsForCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("buildKeyUsagesExtensionsForCertificate() got = %v, want %v", got, tt.want)
			}
		})
	}
}
