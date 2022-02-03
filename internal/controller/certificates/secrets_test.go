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

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func Test_AnnotationsForCertificateSecret(t *testing.T) {
	var urls []*url.URL
	for _, u := range []string{"spiffe.io//cert-manager.io/test", "spiffe.io//hello.world"} {
		url, err := url.Parse(u)
		assert.NoError(t, err)
		urls = append(urls, url)
	}

	tests := map[string]struct {
		crt            *cmapi.Certificate
		certificate    *x509.Certificate
		expAnnotations map[string]string
	}{
		"if pass non-nil certificate, expect all Annotations to be present": {
			crt: gen.Certificate("test-certificate",
				gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "another-test-issuer", Kind: "GoogleCASIssuer", Group: "my-group.hello.world"}),
			),
			certificate: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "cert-manager",
				},
				DNSNames:    []string{"example.com", "cert-manager.io"},
				IPAddresses: []net.IP{{1, 1, 1, 1}, {1, 2, 3, 4}},
				URIs:        urls,
			},
			expAnnotations: map[string]string{
				"cert-manager.io/certificate-name": "test-certificate",
				"cert-manager.io/issuer-name":      "another-test-issuer",
				"cert-manager.io/issuer-kind":      "GoogleCASIssuer",
				"cert-manager.io/issuer-group":     "my-group.hello.world",
				"cert-manager.io/common-name":      "cert-manager",
				"cert-manager.io/alt-names":        "example.com,cert-manager.io",
				"cert-manager.io/ip-sans":          "1.1.1.1,1.2.3.4",
				"cert-manager.io/uri-sans":         "spiffe.io//cert-manager.io/test,spiffe.io//hello.world",
			},
		},
		"if pass non-nil certificate with only CommonName, expect all Annotations to be present": {
			crt: gen.Certificate("test-certificate",
				gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "another-test-issuer", Kind: "GoogleCASIssuer", Group: "my-group.hello.world"}),
			),
			certificate: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "cert-manager",
				},
			},
			expAnnotations: map[string]string{
				"cert-manager.io/certificate-name": "test-certificate",
				"cert-manager.io/issuer-name":      "another-test-issuer",
				"cert-manager.io/issuer-kind":      "GoogleCASIssuer",
				"cert-manager.io/issuer-group":     "my-group.hello.world",
				"cert-manager.io/common-name":      "cert-manager",
				"cert-manager.io/alt-names":        "",
				"cert-manager.io/ip-sans":          "",
				"cert-manager.io/uri-sans":         "",
			},
		},
		"if pass non-nil certificate with only IP Addresses, expect all Annotations to be present": {
			crt: gen.Certificate("test-certificate",
				gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "another-test-issuer", Kind: "GoogleCASIssuer", Group: "my-group.hello.world"}),
			),
			certificate: &x509.Certificate{
				IPAddresses: []net.IP{{1, 1, 1, 1}, {1, 2, 3, 4}},
			},
			expAnnotations: map[string]string{
				"cert-manager.io/certificate-name": "test-certificate",
				"cert-manager.io/issuer-name":      "another-test-issuer",
				"cert-manager.io/issuer-kind":      "GoogleCASIssuer",
				"cert-manager.io/issuer-group":     "my-group.hello.world",
				"cert-manager.io/common-name":      "",
				"cert-manager.io/alt-names":        "",
				"cert-manager.io/ip-sans":          "1.1.1.1,1.2.3.4",
				"cert-manager.io/uri-sans":         "",
			},
		},
		"if pass non-nil certificate with only URI SANs, expect all Annotations to be present": {
			crt: gen.Certificate("test-certificate",
				gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "another-test-issuer", Kind: "GoogleCASIssuer", Group: "my-group.hello.world"}),
			),
			certificate: &x509.Certificate{
				URIs: urls,
			},
			expAnnotations: map[string]string{
				"cert-manager.io/certificate-name": "test-certificate",
				"cert-manager.io/issuer-name":      "another-test-issuer",
				"cert-manager.io/issuer-kind":      "GoogleCASIssuer",
				"cert-manager.io/issuer-group":     "my-group.hello.world",
				"cert-manager.io/common-name":      "",
				"cert-manager.io/alt-names":        "",
				"cert-manager.io/ip-sans":          "",
				"cert-manager.io/uri-sans":         "spiffe.io//cert-manager.io/test,spiffe.io//hello.world",
			},
		},
		"if pass non-nil certificate with only DNS names, expect all Annotations to be present": {
			crt: gen.Certificate("test-certificate",
				gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "another-test-issuer", Kind: "GoogleCASIssuer", Group: "my-group.hello.world"}),
			),
			certificate: &x509.Certificate{
				DNSNames: []string{"example.com", "cert-manager.io"},
			},
			expAnnotations: map[string]string{
				"cert-manager.io/certificate-name": "test-certificate",
				"cert-manager.io/issuer-name":      "another-test-issuer",
				"cert-manager.io/issuer-kind":      "GoogleCASIssuer",
				"cert-manager.io/issuer-group":     "my-group.hello.world",
				"cert-manager.io/common-name":      "",
				"cert-manager.io/alt-names":        "example.com,cert-manager.io",
				"cert-manager.io/ip-sans":          "",
				"cert-manager.io/uri-sans":         "",
			},
		},
		"if no certificate data, then expect no X.509 related annotations": {
			crt: gen.Certificate("test-certificate",
				gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "test-issuer", Kind: "", Group: "cert-manager.io"}),
			),
			certificate: nil,
			expAnnotations: map[string]string{
				"cert-manager.io/certificate-name": "test-certificate",
				"cert-manager.io/issuer-name":      "test-issuer",
				"cert-manager.io/issuer-kind":      "Issuer",
				"cert-manager.io/issuer-group":     "cert-manager.io",
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotAnnotations := AnnotationsForCertificateSecret(test.crt, test.certificate)
			assert.Equal(t, test.expAnnotations, gotAnnotations)
		})
	}
}
