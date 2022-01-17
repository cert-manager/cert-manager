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
	"crypto"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/pmezard/go-difflib/difflib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	testcrypto "github.com/cert-manager/cert-manager/test/unit/crypto"
)

func mustGenerateRSA(t *testing.T, keySize int) crypto.PrivateKey {
	pk, err := pki.GenerateRSAPrivateKey(keySize)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func mustGenerateECDSA(t *testing.T, keySize int) crypto.PrivateKey {
	pk, err := pki.GenerateECPrivateKey(keySize)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func mustGenerateEd25519(t *testing.T) crypto.PrivateKey {
	pk, err := pki.GenerateEd25519PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func TestPrivateKeyMatchesSpec(t *testing.T) {
	tests := map[string]struct {
		key          crypto.PrivateKey
		expectedAlgo cmapi.PrivateKeyAlgorithm
		expectedSize int
		violations   []string
		err          string
	}{
		"should match if keySize and algorithm are correct (RSA)": {
			key:          mustGenerateRSA(t, 2048),
			expectedAlgo: cmapi.RSAKeyAlgorithm,
			expectedSize: 2048,
		},
		"should not match if RSA keySize is incorrect": {
			key:          mustGenerateRSA(t, 2048),
			expectedAlgo: cmapi.RSAKeyAlgorithm,
			expectedSize: 4096,
			violations:   []string{"spec.keySize"},
		},
		"should match if keySize and algorithm are correct (ECDSA)": {
			key:          mustGenerateECDSA(t, pki.ECCurve256),
			expectedAlgo: cmapi.ECDSAKeyAlgorithm,
			expectedSize: 256,
		},
		"should not match if ECDSA keySize is incorrect": {
			key:          mustGenerateECDSA(t, pki.ECCurve256),
			expectedAlgo: cmapi.ECDSAKeyAlgorithm,
			expectedSize: pki.ECCurve521,
			violations:   []string{"spec.keySize"},
		},
		"should not match if keyAlgorithm is incorrect": {
			key:          mustGenerateECDSA(t, pki.ECCurve256),
			expectedAlgo: cmapi.RSAKeyAlgorithm,
			expectedSize: 2048,
			violations:   []string{"spec.keyAlgorithm"},
		},
		"should match if keySize and algorithm are correct (Ed25519)": {
			key:          mustGenerateEd25519(t),
			expectedAlgo: cmapi.Ed25519KeyAlgorithm,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			violations, err := PrivateKeyMatchesSpec(
				test.key,
				cmapi.CertificateSpec{
					PrivateKey: &cmapi.CertificatePrivateKey{
						Algorithm: test.expectedAlgo,
						Size:      test.expectedSize,
					},
				},
			)
			switch {
			case err != nil:
				if test.err != err.Error() {
					t.Errorf("error text did not match, got=%s, exp=%s", err.Error(), test.err)
				}
			default:
				if test.err != "" {
					t.Errorf("got no error but expected: %s", test.err)
				}
			}
			if !reflect.DeepEqual(violations, test.violations) {
				t.Errorf("violations did not match, got=%s, exp=%s", violations, test.violations)
			}
		})
	}
}

func TestSecretDataAltNamesMatchSpec(t *testing.T) {
	tests := map[string]struct {
		data       []byte
		spec       cmapi.CertificateSpec
		err        string
		violations []string
	}{
		"should match if common name and dns names exactly equal": {
			spec: cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one"},
			}),
		},
		"should match if commonName is missing but is present in dnsNames": {
			spec: cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				DNSNames: []string{"cn", "at", "least", "one"},
			}),
		},
		"should match if commonName is missing but is present in dnsNames (not first)": {
			spec: cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				DNSNames: []string{"at", "least", "one", "cn"},
			}),
		},
		"should match if commonName is one of the requested requested dnsNames": {
			spec: cmapi.CertificateSpec{
				DNSNames: []string{"at", "least", "one"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				CommonName: "at",
				DNSNames:   []string{"least", "one"},
			}),
		},
		"should not match if commonName is not present on certificate": {
			spec: cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				DNSNames: []string{"at", "least", "one"},
			}),
			violations: []string{"spec.commonName"},
		},
		"should report violation for both commonName and dnsNames if both are missing": {
			spec: cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one", "other"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				DNSNames: []string{"at", "least", "one"},
			}),
			violations: []string{"spec.commonName", "spec.dnsNames"},
		},
		"should report violation for both commonName and dnsNames if not requested": {
			spec: cmapi.CertificateSpec{
				DNSNames: []string{"at", "least", "one"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one", "other"},
			}),
			violations: []string{"spec.commonName", "spec.dnsNames"},
		},
		"should not match if certificate has more dnsNames than spec": {
			spec: cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one", "other"},
			}),
			violations: []string{"spec.dnsNames"},
		},
		"should match if commonName is a duplicated dnsName (but not requested)": {
			spec: cmapi.CertificateSpec{
				DNSNames: []string{"at", "least", "one"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				CommonName: "at",
				DNSNames:   []string{"at", "least", "one"},
			}),
		},
		"should match if commonName is a duplicated dnsName": {
			spec: cmapi.CertificateSpec{
				CommonName: "cn",
				DNSNames:   []string{"at", "least", "one"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				CommonName: "at",
				DNSNames:   []string{"at", "least", "one", "cn"},
			}),
		},
		"should match if ipAddresses are equal": {
			spec: cmapi.CertificateSpec{
				IPAddresses: []string{"127.0.0.1"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				IPAddresses: []string{"127.0.0.1"},
			}),
		},
		"should not match if ipAddresses are not equal": {
			spec: cmapi.CertificateSpec{
				IPAddresses: []string{"127.0.0.1"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				IPAddresses: []string{"127.0.2.1"},
			}),
			violations: []string{"spec.ipAddresses"},
		},
		"should not match if ipAddresses has been made the commonName": {
			spec: cmapi.CertificateSpec{
				IPAddresses: []string{"127.0.0.1"},
			},
			data: selfSignCertificate(t, cmapi.CertificateSpec{
				CommonName:  "127.0.0.1",
				IPAddresses: []string{"127.0.0.1"},
			}),
			violations: []string{"spec.commonName"},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			violations, err := SecretDataAltNamesMatchSpec(&corev1.Secret{Data: map[string][]byte{corev1.TLSCertKey: test.data}}, test.spec)
			switch {
			case err != nil:
				if test.err != err.Error() {
					t.Errorf("error text did not match, got=%s, exp=%s", err.Error(), test.err)
				}
			default:
				if test.err != "" {
					t.Errorf("got no error but expected: %s", test.err)
				}
			}
			if !reflect.DeepEqual(violations, test.violations) {
				t.Errorf("violations did not match, got=%s, exp=%s", violations, test.violations)
			}
		})
	}
}

func selfSignCertificate(t *testing.T, spec cmapi.CertificateSpec) []byte {
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	template, err := pki.GenerateTemplate(&cmapi.Certificate{Spec: spec})
	if err != nil {
		t.Fatal(err)
	}

	pemData, _, err := pki.SignCertificate(template, template, pk.Public(), pk)
	if err != nil {
		t.Fatal(err)
	}

	return pemData
}

func TestRenewalTime(t *testing.T) {
	type scenario struct {
		notBefore           time.Time
		notAfter            time.Time
		renewBeforeOverride *metav1.Duration
		expectedRenewalTime *metav1.Time
	}
	now := time.Now().Truncate(time.Second)
	tests := map[string]scenario{
		"short lived cert, spec.renewBefore is not set": {
			notBefore:           now,
			notAfter:            now.Add(time.Hour * 3),
			renewBeforeOverride: nil,
			expectedRenewalTime: &metav1.Time{Time: now.Add(time.Hour * 2)},
		},
		"long lived cert, spec.renewBefore is not set": {
			notBefore:           now,
			notAfter:            now.Add(time.Hour * 4380), // 6 months
			renewBeforeOverride: nil,
			expectedRenewalTime: &metav1.Time{Time: now.Add(time.Hour * 2920)}, // renew in 4 months
		},
		"spec.renewBefore is set": {
			notBefore:           now,
			notAfter:            now.Add(time.Hour * 24),
			renewBeforeOverride: &metav1.Duration{Duration: time.Hour * 20},
			expectedRenewalTime: &metav1.Time{Time: now.Add(time.Hour * 4)},
		},
		"long lived cert, spec.renewBefore is set to renew every day": {
			notBefore:           now,
			notAfter:            now.Add(time.Hour * 730),                    // 1 month
			renewBeforeOverride: &metav1.Duration{Duration: time.Hour * 706}, // 1 month - 1 day
			expectedRenewalTime: &metav1.Time{Time: now.Add(time.Hour * 24)},
		},
		"spec.renewBefore is set, but would result in renewal time after expiry": {
			notBefore:           now,
			notAfter:            now.Add(time.Hour * 24),
			renewBeforeOverride: &metav1.Duration{Duration: time.Hour * 25},
			expectedRenewalTime: &metav1.Time{Time: now.Add(time.Hour * 16)},
		},
		// This test case is here to show the scenario where users set
		// renewBefore to very slightly less than actual duration. This
		// will result in cert being renewed 'continuously'.
		"spec.renewBefore is set to a value slightly less than cert's duration": {
			notBefore:           now,
			notAfter:            now.Add(time.Hour*24 + time.Minute*3),
			renewBeforeOverride: &metav1.Duration{Duration: time.Hour * 24},
			expectedRenewalTime: &metav1.Time{Time: now.Add(time.Minute * 3)}, // renew in 3 minutes
		},
		// This test case is here to guard against an earlier bug where
		// a non-truncated renewal time returned from this function
		// caused certs to not be renewed.
		// See https://github.com/cert-manager/cert-manager/pull/4399
		"certificate's duration is skewed by a second": {
			notBefore:           now,
			notAfter:            now.Add(time.Hour * 24).Add(time.Second * -1),
			expectedRenewalTime: &metav1.Time{Time: now.Add(time.Hour * 16).Add(time.Second * -1)},
		},
	}
	for n, s := range tests {
		t.Run(n, func(t *testing.T) {
			renewalTime := RenewalTime(s.notBefore, s.notAfter, s.renewBeforeOverride)
			assert.Equal(t, s.expectedRenewalTime, renewalTime, fmt.Sprintf("Expected renewal time: %v got: %v", s.expectedRenewalTime, renewalTime))

		})
	}
}

func TestRequestMatchesSpec(t *testing.T) {
	type Cert cmapi.Certificate // Those long types are making the lines go wee!
	staticFixedPrivateKey := testcrypto.MustCreatePEMPrivateKey(t)

	originalCert := &cmapi.Certificate{Spec: cmapi.CertificateSpec{
		CommonName: "does-not-matter.example.com",
		Subject: &cmapi.X509Subject{
			Organizations:       []string{"org1", "org2"},
			Countries:           []string{"us"},
			OrganizationalUnits: []string{"ou1", "ou2"},
			Localities:          []string{"loc1", "loc2"},
			Provinces:           []string{"prov1", "prov2"},
			StreetAddresses:     []string{"street1", "street2"},
			PostalCodes:         []string{"post1", "post2"},
			SerialNumber:        "12345",
		},
		Duration:       &metav1.Duration{Duration: 30 * 24 * time.Hour},
		RenewBefore:    &metav1.Duration{Duration: 90 * 24 * time.Hour},
		DNSNames:       []string{"example.com"},
		IPAddresses:    []string{"1.2.3.4"},
		URIs:           []string{"http://example.com"},
		EmailAddresses: []string{"foo@bar.com"},
		SecretName:     "does-not-matter",
		SecretTemplate: &cmapi.CertificateSecretTemplate{
			Labels: map[string]string{"foo": "bar"},
		},
		Keystores: &cmapi.CertificateKeystores{
			JKS: &cmapi.JKSKeystore{
				Create: true,
				PasswordSecretRef: cmmeta.SecretKeySelector{
					Key:                  "password",
					LocalObjectReference: cmmeta.LocalObjectReference{Name: "foo"},
				},
			},
			PKCS12: &cmapi.PKCS12Keystore{
				Create: true,
				PasswordSecretRef: cmmeta.SecretKeySelector{
					Key:                  "password",
					LocalObjectReference: cmmeta.LocalObjectReference{Name: "foo"},
				},
			},
		},
		IssuerRef: cmmeta.ObjectReference{
			Name:  "testissuer",
			Kind:  "IssuerKind",
			Group: "group.example.com",
		},
		IsCA: true,
		Usages: []cmapi.KeyUsage{
			cmapi.UsageSigning,
			cmapi.UsageDigitalSignature,
			cmapi.UsageKeyEncipherment,
		},
		PrivateKey: &cmapi.CertificatePrivateKey{
			Algorithm:      cmapi.RSAKeyAlgorithm,
			Size:           2048,
			RotationPolicy: cmapi.RotationPolicyNever,
			Encoding:       cmapi.PKCS8,
		},
		EncodeUsagesInRequest: pointer.Bool(true),
		RevisionHistoryLimit:  pointer.Int32(2),
	}}
	originalCR := &cmapi.CertificateRequest{Spec: cmapi.CertificateRequestSpec{
		IssuerRef: cmmeta.ObjectReference{
			Name:  "testissuer",
			Kind:  "IssuerKind",
			Group: "group.example.com",
		},
		Request: testcrypto.MustGenerateCSRImpl(t, staticFixedPrivateKey, originalCert),
		IsCA:    true,
		Usages: []cmapi.KeyUsage{
			cmapi.UsageSigning,
			cmapi.UsageDigitalSignature,
			cmapi.UsageKeyEncipherment,
		},
		Duration: &metav1.Duration{Duration: 30 * 24 * time.Hour},
	}}

	tests := []struct {
		change     func(c *Cert) // Nil if no change is to be made.
		mismatches []string
	}{
		// Happy case: with no change to the Certificate, no mismatch is
		// expected.
		{change: nil, mismatches: nil},

		// The following Certificate fields are looked up by the
		// RequestMatchesSpec function.
		{change: func(c *Cert) { c.Spec.CommonName = "changed" }, mismatches: []string{"spec.commonName"}},
		{change: func(c *Cert) { c.Spec.DNSNames = []string{"changed"} }, mismatches: []string{"spec.dnsNames"}},
		{change: func(c *Cert) { c.Spec.IPAddresses = []string{"4.3.2.1"} }, mismatches: []string{"spec.ipAddresses"}},
		{change: func(c *Cert) { c.Spec.URIs = []string{"https://changed"} }, mismatches: []string{"spec.uris"}},
		{change: func(c *Cert) { c.Spec.EmailAddresses = []string{"changed@bar.com"} }, mismatches: []string{"spec.emailAddresses"}},
		{change: func(c *Cert) { c.Spec.Usages = []cmapi.KeyUsage{cmapi.UsageAny} }, mismatches: []string{"spec.usages"}},
		{change: func(c *Cert) { c.Spec.IsCA = false }, mismatches: []string{"spec.isCA"}},
		{change: func(c *Cert) { c.Spec.Duration = &metav1.Duration{Duration: 1 * time.Hour} }, mismatches: []string{"spec.duration"}},
		{change: func(c *Cert) { c.Spec.IssuerRef = cmmeta.ObjectReference{Name: "changed"} }, mismatches: []string{"spec.issuerRef"}},

		// The following Certificate fields are not looked at by the
		// RequestMatchesSpec function.
		{change: func(c *Cert) { c.Spec.PrivateKey.Algorithm = cmapi.ECDSAKeyAlgorithm }, mismatches: nil},
		{change: func(c *Cert) { c.Spec.PrivateKey.Size = 4096 }, mismatches: nil},
		{change: func(c *Cert) { c.Spec.EncodeUsagesInRequest = pointer.Bool(false) }, mismatches: nil},
		{change: func(c *Cert) { c.Spec.Keystores = &cmapi.CertificateKeystores{} }, mismatches: nil},
		{change: func(c *Cert) { c.Spec.RenewBefore = &metav1.Duration{Duration: 1 * time.Hour} }, mismatches: nil},
		{change: func(c *Cert) { c.Spec.RevisionHistoryLimit = pointer.Int32(10) }, mismatches: nil},
		{change: func(c *Cert) { c.Spec.SecretName = "changed" }, mismatches: nil}, // (1)
		{change: func(c *Cert) { c.Spec.SecretTemplate = &cmapi.CertificateSecretTemplate{} }, mismatches: nil},
		{change: func(c *Cert) { c.Spec.PrivateKey.Encoding = cmapi.PKCS1 }, mismatches: nil},
		{change: func(c *Cert) { c.Spec.PrivateKey.RotationPolicy = cmapi.RotationPolicyAlways }, mismatches: nil},
	}

	for _, test := range tests {
		t.Run("", func(t *testing.T) {
			cert := originalCert.DeepCopy()
			var diffCert string
			if test.change != nil {
				test.change((*Cert)(cert))
				diffCert, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
					A:       difflib.SplitLines(spewConf.Sdump(originalCert)),
					B:       difflib.SplitLines(spewConf.Sdump(cert)),
					Context: 1,
				})
				if test.change != nil && diffCert == "" {
					t.Fatal("incorrect test case: the func to change the Certificate is non-nil but no change has been detected on the Certificate")
				}
			}
			gotMismatches, gotErr := RequestMatchesSpec(originalCR, cert.Spec)
			require.NoError(t, gotErr)

			if !reflect.DeepEqual(test.mismatches, gotMismatches) {
				debug := ""
				if diffCert == "" {
					debug += "with no change to the Certificate"
				} else {
					debug += fmt.Sprintf("with the following changes to the Certificate : %s", diffCert)
				}
				t.Errorf("%s, expected mismatches=%v but got mismatches=%v", debug, test.mismatches, gotMismatches)
			}
		})
	}
}

var spewConf = spew.ConfigState{
	Indent:                  " ",
	DisablePointerAddresses: true,
	DisableCapacities:       true,
	SortKeys:                true,
	DisableMethods:          true,
	MaxDepth:                10,
}
