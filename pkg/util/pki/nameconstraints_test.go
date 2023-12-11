/*
Copyright 2023 The cert-manager Authors.

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
	"encoding/pem"
	"fmt"
	"os"
	"testing"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/stretchr/testify/assert"
)

// TestMarshalNameConstraints tests the MarshalNameConstraints function
// To generate the testdata at testdata/nameconstraints, do something like this:
// openssl req -new -key private_key.pem -out csr1.pem -subj "/CN=example.org" -config config.cnf
//
// where config.cnf is(replace nameConstraints with the values mentioned in the testcase):
// [req]
// default_bits        = 2048
// prompt              = no
// default_md          = sha256
// req_extensions      = req_ext

// [req_ext]
// nameConstraints = critical,permitted;DNS:example.com,permitted;IP:192.168.1.0/255.255.255.0,permitted;email:user@example.com,permitted;URI:https://example.com,excluded;DNS:excluded.com,excluded;IP:192.168.0.0/255.255.255.0,excluded;email:user@excluded.com,excluded;URI:https://excluded.com
func TestMarshalNameConstraints(t *testing.T) {
	// Test data
	testCases := []struct {
		name         string
		input        *v1.NameConstraints
		expectedErr  error
		expectedFile string
	}{
		{
			name: "Permitted constraints",
			input: &v1.NameConstraints{
				Critical: true,
				Permitted: &v1.NameConstraintItem{
					DNSDomains:     []string{"example.com"},
					IPRanges:       []string{"192.168.1.0/24"},
					EmailAddresses: []string{"user@example.com"},
					URIDomains:     []string{"https://example.com"},
				},
			},
			expectedErr: nil,
			// nameConstraints = critical,permitted;DNS:example.com,permitted;IP:192.168.1.0/255.255.255.0,permitted;email:user@example.com,permitted;URI:https://example.com
			expectedFile: "permitted-constraints.pem",
		},
		{
			name: "Mixed constraints",
			input: &v1.NameConstraints{
				Critical: true,
				Permitted: &v1.NameConstraintItem{
					DNSDomains:     []string{"example.com"},
					IPRanges:       []string{"192.168.1.0/24"},
					EmailAddresses: []string{"user@example.com"},
					URIDomains:     []string{"https://example.com"},
				},
				Excluded: &v1.NameConstraintItem{
					DNSDomains:     []string{"excluded.com"},
					IPRanges:       []string{"192.168.0.0/24"},
					EmailAddresses: []string{"user@excluded.com"},
					URIDomains:     []string{"https://excluded.com"},
				},
			},
			expectedErr: nil,
			// nameConstraints = critical,permitted;DNS:example.com,permitted;IP:192.168.1.0/255.255.255.0,permitted;email:user@example.com,permitted;URI:https://example.com,excluded;DNS:excluded.com,excluded;IP:192.168.0.0/255.255.255.0,excluded;email:user@excluded.com,excluded;URI:https://excluded.com
			expectedFile: "mixed-constraints.pem",
		},
		{
			name:         "Empty constraints",
			input:        &v1.NameConstraints{},
			expectedErr:  nil,
			expectedFile: "",
		},
		{
			name: "Excluded constraints",
			input: &v1.NameConstraints{
				Critical: true,
				Excluded: &v1.NameConstraintItem{
					DNSDomains:     []string{"excluded.com"},
					IPRanges:       []string{"192.168.0.0/24"},
					EmailAddresses: []string{"user@excluded.com"},
					URIDomains:     []string{"https://excluded.com"},
				},
			},
			expectedErr: nil,
			// nameConstraints = critical,excluded;DNS:excluded.com,excluded;IP:192.168.0.0/255.255.255.0,excluded;email:user@excluded.com,excluded;URI:https://excluded.com
			expectedFile: "excluded-constraints.pem",
		},
		{
			name: "Invalid NameConstraints",
			input: &v1.NameConstraints{
				Excluded: &v1.NameConstraintItem{
					IPRanges: []string{"invalidCIDR"},
				},
			},
			expectedErr:  fmt.Errorf("invalid CIDR address: invalidCIDR"),
			expectedFile: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			expectedResult, err := getExtensionFromFile(tc.expectedFile)
			assert.NoError(t, err)
			result, err := MarshalNameConstraints(tc.input)
			if tc.expectedErr != nil {
				assert.Error(t, err)
				assert.EqualError(t, err, tc.expectedErr.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, expectedResult.Id, result.Id)
				assert.Equal(t, expectedResult.Critical, result.Critical)
				assert.Equal(t, expectedResult.Value, result.Value)
			}
		})
	}
}

func getExtensionFromFile(csrPath string) (pkix.Extension, error) {
	if csrPath == "" {
		return pkix.Extension{}, nil
	}

	csrPEM, err := os.ReadFile("testdata/nameconstraints/" + csrPath)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("Error reading CSR file: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return pkix.Extension{}, fmt.Errorf("Failed to decode PEM block or the type is not 'CERTIFICATE REQUEST'")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("Error parsing CSR: %v", err)
	}

	for _, ext := range csr.Extensions {
		if ext.Id.Equal(OIDExtensionNameConstraints) {
			return ext, nil
		}
	}

	return pkix.Extension{}, nil
}
