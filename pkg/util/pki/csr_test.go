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

package pki

import (
	"crypto/x509"
	"testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util"
)

func buildCertificate(cn string, dnsNames ...string) *v1alpha1.Certificate {
	return &v1alpha1.Certificate{
		Spec: v1alpha1.CertificateSpec{
			CommonName: cn,
			DNSNames:   dnsNames,
		},
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
			expectedCN:  "dnsname",
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
			expectedCN:  "dnsname1",
		},
	}
	testFn := func(test testT) func(*testing.T) {
		return func(t *testing.T) {
			actualCN := CommonNameForCertificate(buildCertificate(test.crtCN, test.crtDNSNames...))
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
			expectDNSNames: []string{"test"},
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
			expectDNSNames: []string{"cn", "dnsname"},
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
			expectDNSNames: []string{"cn", "dnsname"},
		},
	}
	testFn := func(test testT) func(*testing.T) {
		return func(t *testing.T) {
			actualDNSNames := DNSNamesForCertificate(buildCertificate(test.crtCN, test.crtDNSNames...))
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
		keyAlgo         v1alpha1.KeyAlgorithm
		keySize         int
		expectErr       bool
		expectedSigAlgo x509.SignatureAlgorithm
		expectedKeyType x509.PublicKeyAlgorithm
	}

	tests := []testT{
		{
			name:      "certificate with KeyAlgorithm rsa and size 1024",
			keyAlgo:   v1alpha1.RSAKeyAlgorithm,
			keySize:   1024,
			expectErr: true,
		},
		{
			name:            "certificate with KeyAlgorithm rsa and no size set should default to rsa256",
			keyAlgo:         v1alpha1.RSAKeyAlgorithm,
			expectedSigAlgo: x509.SHA256WithRSA,
			expectedKeyType: x509.RSA,
		},
		{
			name:            "certificate with KeyAlgorithm not set",
			keyAlgo:         v1alpha1.KeyAlgorithm(""),
			expectedSigAlgo: x509.SHA256WithRSA,
			expectedKeyType: x509.RSA,
		},
		{
			name:            "certificate with KeyAlgorithm rsa and size 2048",
			keyAlgo:         v1alpha1.RSAKeyAlgorithm,
			keySize:         2048,
			expectedSigAlgo: x509.SHA256WithRSA,
			expectedKeyType: x509.RSA,
		},
		{
			name:            "certificate with KeyAlgorithm rsa and size 3072",
			keyAlgo:         v1alpha1.RSAKeyAlgorithm,
			keySize:         3072,
			expectedSigAlgo: x509.SHA384WithRSA,
			expectedKeyType: x509.RSA,
		},
		{
			name:            "certificate with KeyAlgorithm rsa and size 4096",
			keyAlgo:         v1alpha1.RSAKeyAlgorithm,
			keySize:         4096,
			expectedSigAlgo: x509.SHA512WithRSA,
			expectedKeyType: x509.RSA,
		},
		{
			name:            "certificate with ecdsa key algorithm set and no key size default to ecdsa256",
			keyAlgo:         v1alpha1.ECDSAKeyAlgorithm,
			expectedSigAlgo: x509.ECDSAWithSHA256,
			expectedKeyType: x509.ECDSA,
		},
		{
			name:            "certificate with KeyAlgorithm ecdsa and size 256",
			keyAlgo:         v1alpha1.ECDSAKeyAlgorithm,
			keySize:         256,
			expectedSigAlgo: x509.ECDSAWithSHA256,
			expectedKeyType: x509.ECDSA,
		},
		{
			name:            "certificate with KeyAlgorithm ecdsa and size 384",
			keyAlgo:         v1alpha1.ECDSAKeyAlgorithm,
			keySize:         384,
			expectedSigAlgo: x509.ECDSAWithSHA384,
			expectedKeyType: x509.ECDSA,
		},
		{
			name:            "certificate with KeyAlgorithm ecdsa and size 521",
			keyAlgo:         v1alpha1.ECDSAKeyAlgorithm,
			keySize:         521,
			expectedSigAlgo: x509.ECDSAWithSHA512,
			expectedKeyType: x509.ECDSA,
		},
		{
			name:      "certificate with KeyAlgorithm ecdsa and size 100",
			keyAlgo:   v1alpha1.ECDSAKeyAlgorithm,
			keySize:   100,
			expectErr: true,
		},
		{
			name:      "certificate with KeyAlgorithm set to unknown key algo",
			keyAlgo:   v1alpha1.KeyAlgorithm("blah"),
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
