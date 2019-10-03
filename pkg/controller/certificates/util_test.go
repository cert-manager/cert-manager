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

package certificates

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

func TestCertificateMatchesSpec(t *testing.T) {
	baseCert := gen.Certificate("test",
		gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "ca-issuer", Kind: "Issuer", Group: "not-empty"}),
		gen.SetCertificateSecretName("output"),
		gen.SetCertificateRenewBefore(time.Hour*36),
	)

	exampleBundle := mustCreateCryptoBundle(t, gen.CertificateFrom(baseCert,
		gen.SetCertificateDNSNames("a.example.com"),
		gen.SetCertificateCommonName("common.name.example.com"),
		gen.SetCertificateURIs("spiffe://cluster.local/ns/sandbox/sa/foo"),
	))

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				cmapi.IssuerNameAnnotationKey: "ca-issuer",
				cmapi.IssuerKindAnnotationKey: "Issuer",
			},
		},
	}

	type testT struct {
		cb          cryptoBundle
		certificate *cmapi.Certificate
		secret      *corev1.Secret
		expMatch    bool
		expErrors   []string
	}

	for name, test := range map[string]testT{
		"if all match then return matched": {
			cb:          exampleBundle,
			certificate: exampleBundle.certificate,
			expMatch:    true,
			expErrors:   nil,
		},

		"if no common name but DNS and all match then return matched": {
			cb: mustCreateCryptoBundle(t, gen.CertificateFrom(exampleBundle.certificate,
				gen.SetCertificateCommonName(""),
			)),
			certificate: gen.CertificateFrom(exampleBundle.certificate,
				gen.SetCertificateCommonName(""),
			),
			expMatch:  true,
			expErrors: nil,
		},

		"if common name empty but requested common name in DNS names then match": {
			cb: mustCreateCryptoBundle(t, gen.CertificateFrom(exampleBundle.certificate,
				gen.SetCertificateDNSNames("a.example.com", "common.name.example.com"),
				gen.SetCertificateCommonName(""),
			)),
			certificate: gen.CertificateFrom(exampleBundle.certificate),
			expMatch:    true,
			expErrors:   nil,
		},

		"if common name random string but requested common name in DNS names then match": {
			cb: mustCreateCryptoBundle(t, gen.CertificateFrom(exampleBundle.certificate,
				gen.SetCertificateDNSNames("a.example.com", "common.name.example.com"),
				gen.SetCertificateCommonName("foobar"),
			)),
			certificate: gen.CertificateFrom(exampleBundle.certificate),
			expMatch:    true,
			expErrors:   nil,
		},

		"if common name random string and no request DNS names but request common name then error missing common name": {
			cb: mustCreateCryptoBundle(t, gen.CertificateFrom(exampleBundle.certificate,
				gen.SetCertificateDNSNames(),
				gen.SetCertificateCommonName("foobar"),
			)),
			certificate: gen.CertificateFrom(exampleBundle.certificate),
			expMatch:    false,
			expErrors: []string{
				`Common Name on TLS certificate not up to date ("common.name.example.com"): [foobar]`,
				"DNS names on TLS certificate not up to date: []",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			match, errs := certificateMatchesSpec(
				test.certificate, test.cb.privateKey, test.cb.cert, secret)

			if match != test.expMatch {
				t.Errorf("got unexpected match bool, exp=%t got=%t",
					test.expMatch, match)
			}

			if !util.EqualSorted(test.expErrors, errs) {
				t.Errorf("got unexpected errors, exp=%s got=%s",
					test.expErrors, errs)
			}
		})
	}

}
