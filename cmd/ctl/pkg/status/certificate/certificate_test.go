/*
Copyright 2020 The Jetstack cert-manager contributors.

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

package certificate

import (
	"crypto/x509"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"strings"
	"testing"
)

func TestFormatStringSlice(t *testing.T) {
	tests := map[string]struct {
		slice     []string
		expOutput string
	}{
		// Newlines are part of the expected output
		"Empty slice returns empty string": {
			slice:     []string{},
			expOutput: ``,
		},
		"Slice with one element returns string with one line": {
			slice: []string{"hello"},
			expOutput: `- hello
`,
		},
		"Slice with multiple elements returns string with multiple lines": {
			slice: []string{"hello", "World", "another line"},
			expOutput: `- hello
- World
- another line
`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if actualOutput := formatStringSlice(test.slice); actualOutput != test.expOutput {
				t.Errorf("Unexpected output; expected: \n%s\nactual: \n%s", test.expOutput, actualOutput)
			}
		})
	}
}

func TestCRInfoString(t *testing.T) {
	tests := map[string]struct {
		cr        *cmapi.CertificateRequest
		expOutput string
	}{
		// Newlines are part of the expected output
		"Nil pointer output correct": {
			cr: nil,
			expOutput: `No CertificateRequest found for this Certificate
`,
		},
		"CR with no condition output correct": {
			cr: &cmapi.CertificateRequest{Status: cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{}}},
			expOutput: `CertificateRequest:
  Name: 
  Namespace: 
  Conditions:
    No Conditions set
`,
		},
		"CR with conditions output correct": {
			cr: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{Type: cmapi.CertificateRequestConditionReady, Status: cmmeta.ConditionTrue, Message: "example"},
					}}},
			expOutput: `CertificateRequest:
  Name: 
  Namespace: 
  Conditions:
    Ready: True, Reason: , Message: example
`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			actualOutput := crInfoString(test.cr)
			if strings.TrimSpace(actualOutput) != strings.TrimSpace(test.expOutput) {
				t.Errorf("Unexpected output; expected: \n%s\nactual: \n%s", test.expOutput, actualOutput)
			}
		})
	}
}

func TestKeyUsageToString(t *testing.T) {
	tests := map[string]struct {
		usage     x509.KeyUsage
		expOutput string
	}{
		"no key usage set": {
			usage:     x509.KeyUsage(0),
			expOutput: "",
		},
		"key usage Digital Signature": {
			usage:     x509.KeyUsageDigitalSignature,
			expOutput: "Digital Signature",
		},
		"key usage Digital Signature and Data Encipherment": {
			usage:     x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
			expOutput: "Digital Signature, Data Encipherment",
		},
		"key usage with three usages is ordered": {
			usage:     x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment | x509.KeyUsageContentCommitment,
			expOutput: "Digital Signature, Content Commitment, Data Encipherment",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if actualOutput := keyUsageToString(test.usage); actualOutput != test.expOutput {
				t.Errorf("Unexpected output; expected: \n%s\nactual: \n%s", test.expOutput, actualOutput)
			}
		})
	}
}

func TestExtKeyUsageToString(t *testing.T) {
	tests := map[string]struct {
		extUsage       []x509.ExtKeyUsage
		expOutput      string
		expError       bool
		expErrorOutput string
	}{
		"no extended key usage": {
			extUsage:  []x509.ExtKeyUsage{},
			expOutput: "",
		},
		"extended key usage Any": {
			extUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			expOutput: "Any",
		},
		"multiple extended key usages": {
			extUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection},
			expOutput: "Client Authentication, Email Protection",
		},
		"undefined extended key usage": {
			extUsage:       []x509.ExtKeyUsage{x509.ExtKeyUsage(42)},
			expOutput:      "",
			expError:       true,
			expErrorOutput: "error when converting Extended Usages to string: encountered unknown Extended Usage with code 42",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			actualOutput, err := extKeyUsageToString(test.extUsage)
			if err != nil {
				if !test.expError || test.expErrorOutput != err.Error() {
					t.Errorf("got unexpected error. This test expects an error: %t. expected error: %q, actual error: %q",
						test.expError, test.expErrorOutput, err.Error())
				}
			} else if test.expError {
				t.Errorf("expects error: %q, but did not get any", test.expErrorOutput)
			}
			if actualOutput != test.expOutput {
				t.Errorf("Unexpected output; expected: \n%s\nactual: \n%s", test.expOutput, actualOutput)
			}
		})
	}
}
