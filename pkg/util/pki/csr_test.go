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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	featuregatetesting "k8s.io/component-base/featuregate/testing"

	"github.com/cert-manager/cert-manager/internal/controller/feature"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
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

	exampleLiteralSubject := "CN=actual-cn, OU=FooLong, OU=Bar, O=example.org"
	rawExampleLiteralSubject, err := ParseSubjectStringToRawDerBytes(exampleLiteralSubject)
	if err != nil {
		t.Fatal(err)
	}

	exampleMultiValueRDNLiteralSubject := "CN=actual-cn, OU=FooLong+OU=Bar, O=example.org"
	rawExampleMultiValueRDNLiteralSubject, err := ParseSubjectStringToRawDerBytes(exampleMultiValueRDNLiteralSubject)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name                                    string
		crt                                     *cmapi.Certificate
		want                                    *x509.CertificateRequest
		wantErr                                 bool
		literalCertificateSubjectFeatureEnabled bool
	}{
		{
			name: "Generate CSR from certificate with only DNS",
			crt:  &cmapi.Certificate{Spec: cmapi.CertificateSpec{DNSNames: []string{"example.org"}}},
			want: &x509.CertificateRequest{
				Version:            0,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				DNSNames:           []string{"example.org"},
				ExtraExtensions:    defaultExtraExtensions,
			},
		},
		{
			name: "Generate CSR from certificate with only CN",
			crt:  &cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.org"}},
			want: &x509.CertificateRequest{
				Version:            0,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				Subject:            pkix.Name{CommonName: "example.org"},
				ExtraExtensions:    defaultExtraExtensions,
			},
		},
		{
			name: "Generate CSR from certificate with extended key usages",
			crt:  &cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.org", Usages: []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageIPsecEndSystem}}},
			want: &x509.CertificateRequest{
				Version:            0,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				Subject:            pkix.Name{CommonName: "example.org"},
				ExtraExtensions:    ipsecExtraExtensions,
			},
		},
		{
			name: "Generate CSR from certificate with double signing key usages",
			crt:  &cmapi.Certificate{Spec: cmapi.CertificateSpec{CommonName: "example.org", Usages: []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageSigning}}},
			want: &x509.CertificateRequest{
				Version:            0,
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
		{
			name: "Generate CSR from certficate with literal subject honouring the exact order",
			crt:  &cmapi.Certificate{Spec: cmapi.CertificateSpec{LiteralSubject: exampleLiteralSubject}},
			want: &x509.CertificateRequest{
				Version:            0,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				RawSubject:         rawExampleLiteralSubject,
				ExtraExtensions:    defaultExtraExtensions,
			},
			literalCertificateSubjectFeatureEnabled: true,
		},
		{
			name: "Generate CSR from certficate with literal multi value subject honouring the exact order",
			crt:  &cmapi.Certificate{Spec: cmapi.CertificateSpec{LiteralSubject: exampleMultiValueRDNLiteralSubject}},
			want: &x509.CertificateRequest{
				Version:            0,
				SignatureAlgorithm: x509.SHA256WithRSA,
				PublicKeyAlgorithm: x509.RSA,
				RawSubject:         rawExampleMultiValueRDNLiteralSubject,
				ExtraExtensions:    defaultExtraExtensions,
			},
			literalCertificateSubjectFeatureEnabled: true,
		},
		{
			name:                                    "Error on generating CSR from certificate without CommonName in LiteralSubject, uri names, email address, or ip addresses",
			crt:                                     &cmapi.Certificate{Spec: cmapi.CertificateSpec{LiteralSubject: "O=EmptyOrg"}},
			wantErr:                                 true,
			literalCertificateSubjectFeatureEnabled: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultMutableFeatureGate, feature.LiteralCertificateSubject, tt.literalCertificateSubjectFeatureEnabled)()
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
		crt     *cmapi.Certificate
		want    []pkix.Extension
		wantErr bool
	}{
		{
			name: "Test no usages set",
			crt:  &cmapi.Certificate{},
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
			crt: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					Usages: []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageClientAuth},
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
			crt: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					Usages: []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageServerAuth, cmapi.UsageClientAuth},
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

func TestSignCSRTemplate(t *testing.T) {
	// We want to test the behavior of SignCSRTemplate in various contexts;
	// for that, we construct a chain of four certificates:
	// a root CA, two intermediate CA, and a leaf certificate.

	mustCreatePair := func(issuerCert *x509.Certificate, issuerPK crypto.Signer, name string, isCA bool) ([]byte, *x509.Certificate, *x509.Certificate, crypto.Signer) {
		pk, err := GenerateECPrivateKey(256)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			Version:               2,
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

	rootPEM, rootCert, rootTmpl, rootPK := mustCreatePair(nil, nil, "root", true)
	int1PEM, int1Cert, int1Tmpl, int1PK := mustCreatePair(rootCert, rootPK, "int1", true)
	int2PEM, int2Cert, int2Tmpl, int2PK := mustCreatePair(int1Cert, int1PK, "int2", true)
	leafPEM, _, leafTmpl, _ := mustCreatePair(int2Cert, int2PK, "leaf", false)

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
