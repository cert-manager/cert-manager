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

package certificates

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_AnnotationsForCertificateSecret(t *testing.T) {
	var urls []*url.URL
	for _, u := range []string{"spiffe.io//cert-manager.io/test", "spiffe.io//hello.world"} {
		url, err := url.Parse(u)
		assert.NoError(t, err)
		urls = append(urls, url)
	}

	tests := map[string]struct {
		certificate    *x509.Certificate
		expAnnotations map[string]string
	}{
		"if pass non-nil certificate, expect all Annotations to be present": {
			certificate: &x509.Certificate{
				Version: 3,
				Subject: pkix.Name{
					CommonName:         "cert-manager",
					Organization:       []string{"Example Organization 1", "Example Organization 2"},
					OrganizationalUnit: []string{"Example Organizational Unit 1", "Example Organizational Unit 2"},
					Country:            []string{"Country 1", "Country 2"},
					Province:           []string{"Province 1", "Province 2"},
					Locality:           []string{"City 1", "City 2"},
					StreetAddress:      []string{"1725 Slough Avenue, Suite 200, Scranton Business Park", "123 Example St"},
					PostalCode:         []string{"55555", "12345"},
					SerialNumber:       "12345678",
				},
				DNSNames:       []string{"example.com", "cert-manager.io"},
				IPAddresses:    []net.IP{{1, 1, 1, 1}, {1, 2, 3, 4}},
				URIs:           urls,
				EmailAddresses: []string{"test1@example.com", "test2@cert-manager.io"},
			},
			expAnnotations: map[string]string{
				"cert-manager.io/common-name":                 "cert-manager",
				"cert-manager.io/alt-names":                   "example.com,cert-manager.io",
				"cert-manager.io/ip-sans":                     "1.1.1.1,1.2.3.4",
				"cert-manager.io/uri-sans":                    "spiffe.io//cert-manager.io/test,spiffe.io//hello.world",
				"cert-manager.io/email-sans":                  "test1@example.com,test2@cert-manager.io",
				"cert-manager.io/subject-organizations":       "Example Organization 1,Example Organization 2",
				"cert-manager.io/subject-organizationalunits": "Example Organizational Unit 1,Example Organizational Unit 2",
				"cert-manager.io/subject-countries":           "Country 1,Country 2",
				"cert-manager.io/subject-provinces":           "Province 1,Province 2",
				"cert-manager.io/subject-localities":          "City 1,City 2",
				"cert-manager.io/subject-streetaddresses":     "\"1725 Slough Avenue, Suite 200, Scranton Business Park\",123 Example St",
				"cert-manager.io/subject-postalcodes":         "55555,12345",
				"cert-manager.io/subject-serialnumber":        "12345678",
			},
		},
		"if pass non-nil certificate with only CommonName, expect all Annotations to be present": {
			certificate: &x509.Certificate{
				Version: 3,
				Subject: pkix.Name{
					CommonName: "cert-manager",
				},
			},
			expAnnotations: map[string]string{
				"cert-manager.io/common-name": "cert-manager",
				"cert-manager.io/alt-names":   "",
				"cert-manager.io/ip-sans":     "",
				"cert-manager.io/uri-sans":    "",
			},
		},
		"if pass non-nil certificate with only IP Addresses, expect all Annotations to be present": {
			certificate: &x509.Certificate{
				Version:     3,
				IPAddresses: []net.IP{{1, 1, 1, 1}, {1, 2, 3, 4}},
			},
			expAnnotations: map[string]string{
				"cert-manager.io/common-name": "",
				"cert-manager.io/alt-names":   "",
				"cert-manager.io/ip-sans":     "1.1.1.1,1.2.3.4",
				"cert-manager.io/uri-sans":    "",
			},
		},
		"if pass non-nil certificate with only URI SANs, expect all Annotations to be present": {
			certificate: &x509.Certificate{
				Version: 3,
				URIs:    urls,
			},
			expAnnotations: map[string]string{
				"cert-manager.io/common-name": "",
				"cert-manager.io/alt-names":   "",
				"cert-manager.io/ip-sans":     "",
				"cert-manager.io/uri-sans":    "spiffe.io//cert-manager.io/test,spiffe.io//hello.world",
			},
		},
		"if pass non-nil certificate with only DNS names, expect all Annotations to be present": {
			certificate: &x509.Certificate{
				Version:  3,
				DNSNames: []string{"example.com", "cert-manager.io"},
			},
			expAnnotations: map[string]string{
				"cert-manager.io/common-name": "",
				"cert-manager.io/alt-names":   "example.com,cert-manager.io",
				"cert-manager.io/ip-sans":     "",
				"cert-manager.io/uri-sans":    "",
			},
		},
		"if no certificate data, then expect no X.509 related annotations": {
			certificate:    nil,
			expAnnotations: map[string]string{},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotAnnotations, err := AnnotationsForCertificate(test.certificate)
			assert.Equal(t, test.expAnnotations, gotAnnotations)
			assert.Equal(t, nil, err)
		})
	}
}
