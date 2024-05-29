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
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMarshalNameConstraints tests the MarshalNameConstraints function
// To generate the expectedPEM, do something like this:
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
func TestMarshalUnmarshalNameConstraints(t *testing.T) {
	// Test data
	testCases := []struct {
		name        string
		input       *NameConstraints
		expectedErr error
		expectedPEM string
	}{
		{
			name: "Permitted constraints",
			input: &NameConstraints{
				PermittedDNSDomains:     []string{"example.com"},
				PermittedIPRanges:       []*net.IPNet{{IP: net.IPv4(192, 168, 1, 0), Mask: net.IPv4Mask(255, 255, 255, 0)}},
				PermittedEmailAddresses: []string{"user@example.com"},
				PermittedURIDomains:     []string{"https://example.com"},
			},
			expectedErr: nil,
			// nameConstraints = critical,permitted;DNS:example.com,permitted;IP:192.168.1.0/255.255.255.0,permitted;email:user@example.com,permitted;URI:https://example.com
			expectedPEM: `-----BEGIN CERTIFICATE REQUEST-----
MIICwjCCAaoCAQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5vcmcwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCXy2XEkqESyr8/Y2x1A7AQaQlu3wry8QSmVwcb
QYQ12xpA9derxd6f2qV+UZq/7tSwvaFfcdzbY4MTG+dq3QmlyXNEpVmzg/CbQJpQ
ae/aacnb7MEvPGQpD8eHBt14QdoH0B5qreARa/IND4I+BazEAn9yAWc9o5BQMqPb
5OGa5PMWR8apRyJrMfupMS0R3Nnmi+BP0fWepbOZHzRA6d2rbwkPBNBHQUyinxXS
oIMg/WbrG0tbps8H6PTZg3Ki+XutPm5rFJ3CKVCzIfWLFIa3jHDNbeRc359EgBI9
r1H7ecuPKxhxewugl0NirKIaEgzc609FIP++pmm3J5P10HF7AgMBAAGgZzBlBgkq
hkiG9w0BCQ4xWDBWMFQGA1UdHgEB/wRKMEigRjANggtleGFtcGxlLmNvbTAKhwjA
qAEA////ADASgRB1c2VyQGV4YW1wbGUuY29tMBWGE2h0dHBzOi8vZXhhbXBsZS5j
b20wDQYJKoZIhvcNAQELBQADggEBAG4mhMt9iOGu1LInHW7oZyD8/FILhhafO7NF
OLPLNK37yZmPWn3idIei/oooFspKspLSMqyCGgibr6jo613+6ENCHgzM/MUDrbfP
i0VmriogMVB6qF73Qozylk1HPMcNe32aKsZygFAzKT586aO/F/exMx3NlKWa36m2
rXKPgtD+T4R+hBxmsYAGVWFlvish+L1UIXtxddna4dYHSbLBz+uZXzrxyuJgSQV3
2wF++GJ1zOi47CEUukqQOAZKPCE59erY+vUas8hwMTHMT22D5ZGbdjg6qVBCQdqW
Nu6OGP4KFgW0HWyeGeNBzioGUeyIHFKILLvj2n94WJMqXNyT5eE=
-----END CERTIFICATE REQUEST-----`,
		},
		{
			name: "Mixed constraints",
			input: &NameConstraints{
				PermittedDNSDomains:     []string{"example.com"},
				PermittedIPRanges:       []*net.IPNet{{IP: net.IPv4(192, 168, 1, 0), Mask: net.IPv4Mask(255, 255, 255, 0)}},
				PermittedEmailAddresses: []string{"user@example.com"},
				PermittedURIDomains:     []string{"https://example.com"},
				ExcludedDNSDomains:      []string{"excluded.com"},
				ExcludedIPRanges:        []*net.IPNet{{IP: net.IPv4(192, 168, 0, 0), Mask: net.IPv4Mask(255, 255, 255, 0)}},
				ExcludedEmailAddresses:  []string{"user@excluded.com"},
				ExcludedURIDomains:      []string{"https://excluded.com"},
			},
			expectedErr: nil,
			// nameConstraints = critical,permitted;DNS:example.com,permitted;IP:192.168.1.0/255.255.255.0,permitted;email:user@example.com,permitted;URI:https://example.com,excluded;DNS:excluded.com,excluded;IP:192.168.0.0/255.255.255.0,excluded;email:user@excluded.com,excluded;URI:https://excluded.com
			expectedPEM: `-----BEGIN CERTIFICATE REQUEST-----
MIIDFDCCAfwCAQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5vcmcwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCXy2XEkqESyr8/Y2x1A7AQaQlu3wry8QSmVwcb
QYQ12xpA9derxd6f2qV+UZq/7tSwvaFfcdzbY4MTG+dq3QmlyXNEpVmzg/CbQJpQ
ae/aacnb7MEvPGQpD8eHBt14QdoH0B5qreARa/IND4I+BazEAn9yAWc9o5BQMqPb
5OGa5PMWR8apRyJrMfupMS0R3Nnmi+BP0fWepbOZHzRA6d2rbwkPBNBHQUyinxXS
oIMg/WbrG0tbps8H6PTZg3Ki+XutPm5rFJ3CKVCzIfWLFIa3jHDNbeRc359EgBI9
r1H7ecuPKxhxewugl0NirKIaEgzc609FIP++pmm3J5P10HF7AgMBAAGggbgwgbUG
CSqGSIb3DQEJDjGBpzCBpDCBoQYDVR0eAQH/BIGWMIGToEYwDYILZXhhbXBsZS5j
b20wCocIwKgBAP///wAwEoEQdXNlckBleGFtcGxlLmNvbTAVhhNodHRwczovL2V4
YW1wbGUuY29toUkwDoIMZXhjbHVkZWQuY29tMAqHCMCoAAD///8AMBOBEXVzZXJA
ZXhjbHVkZWQuY29tMBaGFGh0dHBzOi8vZXhjbHVkZWQuY29tMA0GCSqGSIb3DQEB
CwUAA4IBAQCEBMhHw4wbP+aBDViKtvpaMar3ZWYVuV7j2qck5yDlXYGhpTQlwg5C
XEIP7zKM1yGgCITEpA5KML4PV55rEU6TCa2E9oQfy51QQcmSTGYLjolOahpALwzn
38n9e4WBiHwDVMVsSR5Zhw2dy9tqSslAHjp3TFFCcx7gaKoTs6OOJzv784PzX7xp
Vbm68hvWwkdD0lwGJlNkykPmNGxpC1kVn6L1p7LUubWOkkqBHwgny+DW3fPtKpvO
AHpUq+yDI0oaIz6BIfn2Vs7jUSXCZIoQBwajALg9kGqh3O6+ds617+AzxGXk0LBQ
0GsHVWCimOgcqgU5Qg4K6iMUtlDU2WAW
-----END CERTIFICATE REQUEST-----`,
		},
		{
			name: "Excluded constraints",
			input: &NameConstraints{
				ExcludedDNSDomains:     []string{"excluded.com"},
				ExcludedIPRanges:       []*net.IPNet{{IP: net.IPv4(192, 168, 0, 0), Mask: net.IPv4Mask(255, 255, 255, 0)}},
				ExcludedEmailAddresses: []string{"user@excluded.com"},
				ExcludedURIDomains:     []string{"https://excluded.com"},
			},
			expectedErr: nil,
			// nameConstraints = critical,excluded;DNS:excluded.com,excluded;IP:192.168.0.0/255.255.255.0,excluded;email:user@excluded.com,excluded;URI:https://excluded.com
			expectedPEM: `-----BEGIN CERTIFICATE REQUEST-----
MIICxTCCAa0CAQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5vcmcwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCXy2XEkqESyr8/Y2x1A7AQaQlu3wry8QSmVwcb
QYQ12xpA9derxd6f2qV+UZq/7tSwvaFfcdzbY4MTG+dq3QmlyXNEpVmzg/CbQJpQ
ae/aacnb7MEvPGQpD8eHBt14QdoH0B5qreARa/IND4I+BazEAn9yAWc9o5BQMqPb
5OGa5PMWR8apRyJrMfupMS0R3Nnmi+BP0fWepbOZHzRA6d2rbwkPBNBHQUyinxXS
oIMg/WbrG0tbps8H6PTZg3Ki+XutPm5rFJ3CKVCzIfWLFIa3jHDNbeRc359EgBI9
r1H7ecuPKxhxewugl0NirKIaEgzc609FIP++pmm3J5P10HF7AgMBAAGgajBoBgkq
hkiG9w0BCQ4xWzBZMFcGA1UdHgEB/wRNMEuhSTAOggxleGNsdWRlZC5jb20wCocI
wKgAAP///wAwE4ERdXNlckBleGNsdWRlZC5jb20wFoYUaHR0cHM6Ly9leGNsdWRl
ZC5jb20wDQYJKoZIhvcNAQELBQADggEBABQGXpovgvk8Ag+FSv0fVcHAalNrNHkL
8kJmLjJKMjYhrI4KwkrVDwRvm96ueSfDYLMu56Vd/cLzVbqgFNEeGY+7/fwty/PK
PwjPjMC3i09D1JZjrpc2gpIxmrwP/vf1DpxPUVF5wzE9xRiYvKu3/ZHy1d3FYYgT
cpf+w2cqzt2J8imToJUtjbVTACqBwhwRrn7xyP0trvAo1tfHS4qK7urJxbuT+OAf
mYfy24EOPhpvyIyYS+lbkc9wdYT4BSIjQCFNAjcBD+/04SkHgtbFLy0i8xsKcfOy
3haWYno4zTZ0v6LAdn3CgtbvUtFBfIMjmEfsldVZpIbpuSEqjMFDGls=
-----END CERTIFICATE REQUEST-----`,
		},
	}

	compareIPArrays := func(a, b []*net.IPNet) bool {
		if len(a) != len(b) {
			return false
		}

		for i, ipNet := range a {
			if !ipNet.IP.Equal(b[i].IP) || !bytes.Equal(ipNet.Mask, b[i].Mask) {
				return false
			}
		}

		return true
	}

	for _, tc := range testCases {
		t.Run(tc.name+"_marshal", func(t *testing.T) {
			expectedResult, err := getExtensionFromPem(tc.expectedPEM)
			assert.NoError(t, err)
			result, err := MarshalNameConstraints(tc.input, expectedResult.Critical)
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

		t.Run(tc.name+"_unmarshal", func(t *testing.T) {
			expectedResult, err := getExtensionFromPem(tc.expectedPEM)
			assert.NoError(t, err)
			constraints, err := UnmarshalNameConstraints(expectedResult.Value)
			if tc.expectedErr != nil {
				assert.Error(t, err)
				assert.EqualError(t, err, tc.expectedErr.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, constraints.ExcludedDNSDomains, tc.input.ExcludedDNSDomains)
				assert.Equal(t, constraints.ExcludedEmailAddresses, tc.input.ExcludedEmailAddresses)
				assert.True(t, compareIPArrays(constraints.ExcludedIPRanges, tc.input.ExcludedIPRanges))
				assert.Equal(t, constraints.ExcludedURIDomains, tc.input.ExcludedURIDomains)
				assert.Equal(t, constraints.PermittedDNSDomains, tc.input.PermittedDNSDomains)
				assert.Equal(t, constraints.PermittedEmailAddresses, tc.input.PermittedEmailAddresses)
				assert.True(t, compareIPArrays(constraints.PermittedIPRanges, tc.input.PermittedIPRanges))
				assert.Equal(t, constraints.PermittedURIDomains, tc.input.PermittedURIDomains)
			}
		})
	}
}

func getExtensionFromPem(pemData string) (pkix.Extension, error) {
	if pemData == "" {
		return pkix.Extension{}, nil
	}

	pemData = strings.TrimSpace(pemData)
	csrPEM := []byte(pemData)

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
