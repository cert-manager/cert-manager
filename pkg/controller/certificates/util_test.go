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

func TestCertificateSpecMatchesCertificateRequest(t *testing.T) {
	baseCert := gen.Certificate("test",
		gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "ca-issuer", Kind: "Issuer", Group: "not-empty"}),
		gen.SetCertificateSecretName("output"),
		gen.SetCertificateDNSNames("a.example.com", "b.example.com"),
		gen.SetCertificateCommonName("common.name.example.com"),
		gen.SetCertificateURIs("spiffe://cluster.local/ns/sandbox/sa/foo"),
		gen.SetCertificateIPs("8.8.8.8", "127.0.0.1"),
		gen.SetCertificateRenewBefore(time.Hour*36),
	)

	exampleBundle := mustCreateCryptoBundle(t, gen.CertificateFrom(baseCert))

	type testT struct {
		cb          cryptoBundle
		certificate *cmapi.Certificate
		csr         *cmapi.CertificateRequest

		expMatch, expError bool
	}

	for name, test := range map[string]testT{
		"if all match then return matched": {
			certificate: exampleBundle.certificate,
			csr:         exampleBundle.certificateRequest,
			expMatch:    true,
			expError:    false,
		},
		"if badly coded CSR PEM then error": {
			certificate: exampleBundle.certificate,
			csr: gen.CertificateRequestFrom(exampleBundle.certificateRequest,
				gen.SetCertificateRequestCSR([]byte("garbage")),
			),
			expMatch: false,
			expError: true,
		},
		"if common name is different then not match": {
			certificate: exampleBundle.certificate,
			csr: mustCreateCryptoBundle(t, gen.CertificateFrom(baseCert,
				gen.SetCertificateCommonName("different common name"),
			)).certificateRequest,
			expMatch: false,
			expError: false,
		},
		"if IPs do not match then don't match": {
			certificate: exampleBundle.certificate,
			csr: mustCreateCryptoBundle(t, gen.CertificateFrom(baseCert,
				gen.SetCertificateIPs("127.0.0.1"),
			)).certificateRequest,
			expMatch: false,
			expError: false,
		},
		"if URIs do not match then don't match": {
			certificate: exampleBundle.certificate,
			csr: mustCreateCryptoBundle(t, gen.CertificateFrom(baseCert,
				gen.SetCertificateURIs("spiffe://cluster.local/ns/sandbox/sa/foo", "spiffe://cluster.local/ns/sandbox/sa/bar"),
			)).certificateRequest,
			expMatch: false,
			expError: false,
		},
		"if Countries do not match then don't match": {
			certificate: exampleBundle.certificate,
			csr: mustCreateCryptoBundle(t, gen.CertificateFrom(baseCert,
				gen.SetCertificateCountries("hello friends"),
			)).certificateRequest,
			expMatch: false,
			expError: false,
		},
		"if Usages do not match then don't match": {
			certificate: exampleBundle.certificate,
			csr: mustCreateCryptoBundle(t, gen.CertificateFrom(baseCert,
				gen.SetCertificateKeyUsages(cmapi.UsageCertSign),
			)).certificateRequest,
			expMatch: false,
			expError: false,
		},
		"if isCA request does not match then don't match": {
			certificate: exampleBundle.certificate,
			csr: mustCreateCryptoBundle(t, gen.CertificateFrom(baseCert,
				gen.SetCertificateIsCA(true),
			)).certificateRequest,
			expMatch: false,
			expError: false,
		},
		"if Duration does not match then don't match": {
			certificate: exampleBundle.certificate,
			csr: mustCreateCryptoBundle(t, gen.CertificateFrom(baseCert,
				gen.SetCertificateDuration(time.Second),
			)).certificateRequest,
			expMatch: false,
			expError: false,
		},
		"if dnsNames in request does not match then don't match": {
			certificate: exampleBundle.certificate,
			csr: mustCreateCryptoBundle(t, gen.CertificateFrom(baseCert,
				gen.SetCertificateDNSNames("a.example.com"),
			)).certificateRequest,
			expMatch: false,
			expError: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			match, err := certificateSpecMatchesCertificateRequest(
				test.certificate, test.csr)

			if match != test.expMatch {
				t.Errorf("got unexpected match bool, exp=%t got=%t",
					test.expMatch, match)
			}

			if test.expError != (err != nil) {
				t.Errorf("got unexpected error, exp=%t got=%t (%s)",
					test.expError, err != nil, err)
			}
		})
	}
}

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
			secret:      gen.SecretFrom(secret),
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
			secret:    gen.SecretFrom(secret),
			expMatch:  true,
			expErrors: nil,
		},

		"if common name empty but requested common name in DNS names then match": {
			cb: mustCreateCryptoBundle(t, gen.CertificateFrom(exampleBundle.certificate,
				gen.SetCertificateDNSNames("a.example.com", "common.name.example.com"),
				gen.SetCertificateCommonName(""),
			)),
			certificate: gen.CertificateFrom(exampleBundle.certificate),
			secret:      gen.SecretFrom(secret),
			expMatch:    true,
			expErrors:   nil,
		},

		"if common name random string but requested common name in DNS names then match": {
			cb: mustCreateCryptoBundle(t, gen.CertificateFrom(exampleBundle.certificate,
				gen.SetCertificateDNSNames("a.example.com", "common.name.example.com"),
				gen.SetCertificateCommonName("foobar"),
			)),
			certificate: gen.CertificateFrom(exampleBundle.certificate),
			secret:      gen.SecretFrom(secret),
			expMatch:    true,
			expErrors:   nil,
		},

		"if common name random string and no request DNS names but request common name then error missing common name": {
			cb: mustCreateCryptoBundle(t, gen.CertificateFrom(exampleBundle.certificate,
				gen.SetCertificateDNSNames(),
				gen.SetCertificateCommonName("foobar"),
			)),
			certificate: gen.CertificateFrom(exampleBundle.certificate),
			secret:      gen.SecretFrom(secret),
			expMatch:    false,
			expErrors: []string{
				`Common Name on TLS certificate not up to date ("common.name.example.com"): [foobar]`,
				"DNS names on TLS certificate not up to date: []",
			},
		},

		"if the issuer name and kind uses v1alpha2 annotation then it should still match the spec": {
			cb:          mustCreateCryptoBundle(t, gen.CertificateFrom(exampleBundle.certificate)),
			certificate: gen.CertificateFrom(exampleBundle.certificate),
			secret: gen.SecretFrom(secret,
				gen.SetSecretAnnotations(map[string]string{
					cmapi.IssuerNameAnnotationKey: "ca-issuer",
					cmapi.IssuerKindAnnotationKey: "Issuer",
				})),
			expMatch:  true,
			expErrors: nil,
		},

		"if the issuer name uses v1alpha2 annotation but kind uses depreicated then it should still match the spec": {
			cb:          mustCreateCryptoBundle(t, gen.CertificateFrom(exampleBundle.certificate)),
			certificate: gen.CertificateFrom(exampleBundle.certificate),
			secret: gen.SecretFrom(secret,
				gen.SetSecretAnnotations(map[string]string{
					cmapi.IssuerNameAnnotationKey:           "ca-issuer",
					cmapi.DeprecatedIssuerKindAnnotationKey: "Issuer",
				})),
			expMatch:  true,
			expErrors: nil,
		},

		"if the issuer name uses deprecated annotation but kind uses v1alpha2 then it should still match the spec": {
			cb:          mustCreateCryptoBundle(t, gen.CertificateFrom(exampleBundle.certificate)),
			certificate: gen.CertificateFrom(exampleBundle.certificate),
			secret: gen.SecretFrom(secret,
				gen.SetSecretAnnotations(map[string]string{
					cmapi.DeprecatedIssuerNameAnnotationKey: "ca-issuer",
					cmapi.IssuerKindAnnotationKey:           "Issuer",
				})),
			expMatch:  true,
			expErrors: nil,
		},

		"if the issuer name and kind uses the deprecated annotation then it should still match the spec": {
			cb:          mustCreateCryptoBundle(t, gen.CertificateFrom(exampleBundle.certificate)),
			certificate: gen.CertificateFrom(exampleBundle.certificate),
			secret: gen.SecretFrom(secret,
				gen.SetSecretAnnotations(map[string]string{
					cmapi.DeprecatedIssuerNameAnnotationKey: "ca-issuer",
					cmapi.DeprecatedIssuerKindAnnotationKey: "Issuer",
				})),
			expMatch:  true,
			expErrors: nil,
		},

		"if the issuer name uses v1alpha2 and kind uses both the deprecated and v1alpha2 annotation then it should still match the spec": {
			cb:          mustCreateCryptoBundle(t, gen.CertificateFrom(exampleBundle.certificate)),
			certificate: gen.CertificateFrom(exampleBundle.certificate),
			secret: gen.SecretFrom(secret,
				gen.SetSecretAnnotations(map[string]string{
					cmapi.DeprecatedIssuerKindAnnotationKey: "Issuer",
					cmapi.IssuerNameAnnotationKey:           "ca-issuer",
					cmapi.IssuerKindAnnotationKey:           "Issuer",
				})),
			expMatch:  true,
			expErrors: nil,
		},

		"if the issuer name both the deprecated and v1alpha2 annotation and kind uses deprecated then it should still match the spec": {
			cb:          mustCreateCryptoBundle(t, gen.CertificateFrom(exampleBundle.certificate)),
			certificate: gen.CertificateFrom(exampleBundle.certificate),
			secret: gen.SecretFrom(secret,
				gen.SetSecretAnnotations(map[string]string{
					cmapi.DeprecatedIssuerNameAnnotationKey: "Issuer",
					cmapi.IssuerNameAnnotationKey:           "ca-issuer",
					cmapi.IssuerKindAnnotationKey:           "Issuer",
				})),
			expMatch:  true,
			expErrors: nil,
		},

		"if the issuer name and kind uses both the deprecated and v1alpha2 annotation then it should still match the spec": {
			cb:          mustCreateCryptoBundle(t, gen.CertificateFrom(exampleBundle.certificate)),
			certificate: gen.CertificateFrom(exampleBundle.certificate),
			secret: gen.SecretFrom(secret,
				gen.SetSecretAnnotations(map[string]string{
					cmapi.DeprecatedIssuerNameAnnotationKey: "ca-issuer",
					cmapi.DeprecatedIssuerKindAnnotationKey: "Issuer",
					cmapi.IssuerNameAnnotationKey:           "ca-issuer",
					cmapi.IssuerKindAnnotationKey:           "Issuer",
				})),
			expMatch:  true,
			expErrors: nil,
		},

		"if the issuer name and kind uses both the deprecated and v1alpha2 annotation but no values in deprecated annotations then should match spec": {
			cb:          mustCreateCryptoBundle(t, gen.CertificateFrom(exampleBundle.certificate)),
			certificate: gen.CertificateFrom(exampleBundle.certificate),
			secret: gen.SecretFrom(secret,
				gen.SetSecretAnnotations(map[string]string{
					cmapi.DeprecatedIssuerNameAnnotationKey: "foo",
					cmapi.DeprecatedIssuerKindAnnotationKey: "bar",
					cmapi.IssuerNameAnnotationKey:           "ca-issuer",
					cmapi.IssuerKindAnnotationKey:           "Issuer",
				})),
			expMatch:  true,
			expErrors: nil,
		},

		"if the issuer name and kind deprecated annotations are correct but v1alpha2 values are wrong then should not match spec": {
			cb:          mustCreateCryptoBundle(t, gen.CertificateFrom(exampleBundle.certificate)),
			certificate: gen.CertificateFrom(exampleBundle.certificate),
			secret: gen.SecretFrom(secret,
				gen.SetSecretAnnotations(map[string]string{
					cmapi.DeprecatedIssuerNameAnnotationKey: "ca-issuer",
					cmapi.DeprecatedIssuerKindAnnotationKey: "Issuer",
					cmapi.IssuerNameAnnotationKey:           "foo",
					cmapi.IssuerKindAnnotationKey:           "bar",
				})),
			expMatch: false,
			expErrors: []string{
				`Issuer "cert-manager.io/issuer-name" of the certificate is not up to date: "foo"`,
				`Issuer "cert-manager.io/issuer-kind" of the certificate is not up to date: "bar"`,
			},
		},

		"if the issuer name and kind deprecated annotations are correct but v1alpha2 values are empty but exist then should not match spec": {
			cb:          mustCreateCryptoBundle(t, gen.CertificateFrom(exampleBundle.certificate)),
			certificate: gen.CertificateFrom(exampleBundle.certificate),
			secret: gen.SecretFrom(secret,
				gen.SetSecretAnnotations(map[string]string{
					cmapi.DeprecatedIssuerNameAnnotationKey: "ca-issuer",
					cmapi.DeprecatedIssuerKindAnnotationKey: "Issuer",
					cmapi.IssuerNameAnnotationKey:           "",
					cmapi.IssuerKindAnnotationKey:           "",
				})),
			expMatch: false,
			expErrors: []string{
				`Issuer "cert-manager.io/issuer-name" of the certificate is not up to date: ""`,
				`Issuer "cert-manager.io/issuer-kind" of the certificate is not up to date: ""`,
			},
		},
		"if the issuer name and kind deprecated annotations are wrong and no v1alpha2 values then should not match spec": {
			cb:          mustCreateCryptoBundle(t, gen.CertificateFrom(exampleBundle.certificate)),
			certificate: gen.CertificateFrom(exampleBundle.certificate),
			secret: gen.SecretFrom(secret,
				gen.SetSecretAnnotations(map[string]string{
					cmapi.DeprecatedIssuerNameAnnotationKey: "foo",
					cmapi.DeprecatedIssuerKindAnnotationKey: "bar",
				})),
			expMatch: false,
			expErrors: []string{
				`Issuer "certmanager.k8s.io/issuer-name" of the certificate is not up to date: "foo"`,
				`Issuer "certmanager.k8s.io/issuer-kind" of the certificate is not up to date: "bar"`,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			match, errs := certificateMatchesSpec(
				test.certificate, test.cb.privateKey, test.cb.cert, test.secret)

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
