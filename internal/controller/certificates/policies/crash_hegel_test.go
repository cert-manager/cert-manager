/*
Copyright 2026 The cert-manager Authors.

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

package policies

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeclock "k8s.io/utils/clock/testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"

	"hegel.dev/go/hegel"
)

// selfSignedPEM returns a private key PEM and a matching self-signed
// certificate PEM for use as "plausible" secret data.
func selfSignedPEM(t *testing.T) (keyPEM, certPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestPolicyChainsNeverPanic feeds arbitrary Certificate/Secret/
// CertificateRequest combinations - including corrupt, truncated and
// mismatched PEM data - through the trigger and readiness policy chains.
// Property: the chains may fail the input for any reason, but must never
// panic, because they run in the certificates reconcilers against
// user-controlled Secret data.
func TestPolicyChainsNeverPanic(t *testing.T) {
	keyPEM, certPEM := selfSignedPEM(t)
	otherKeyPEM, otherCertPEM := selfSignedPEM(t)

	clock := fakeclock.NewFakeClock(time.Now())
	chains := map[string]Chain{
		"trigger":   NewTriggerPolicyChain(clock),
		"readiness": NewReadinessPolicyChain(clock),
	}

	secretValues := hegel.OneOf(
		hegel.Just([]byte(nil)),
		hegel.Just(keyPEM),
		hegel.Just(certPEM),
		hegel.Just(otherKeyPEM),
		hegel.Just(otherCertPEM),
		hegel.Just(certPEM[:len(certPEM)/2]),
		hegel.Binary(0, 64),
	)
	annotationKeys := hegel.SampledFrom([]string{
		cmapi.IssuerNameAnnotationKey,
		cmapi.IssuerKindAnnotationKey,
		cmapi.IssuerGroupAnnotationKey,
		cmapi.CertificateNameKey,
		cmapi.CertificateRequestRevisionAnnotationKey,
		"example.com/unrelated",
	})

	hegel.Test(t, func(ht *hegel.T) {
		crt := &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: "ns"},
			Spec: cmapi.CertificateSpec{
				SecretName: "s",
				CommonName: hegel.Draw(ht, hegel.Text().MaxSize(20)),
				DNSNames:   hegel.Draw(ht, hegel.Lists(hegel.Text().MaxSize(20)).MaxSize(3)),
				IssuerRef: cmmeta.IssuerReference{
					Name: "i",
					Kind: hegel.Draw(ht, hegel.SampledFrom([]string{"", "Issuer", "ClusterIssuer"})),
				},
			},
		}
		if d := hegel.Draw(ht, hegel.Optional(hegel.Integers[int64](-3600, 90*24*3600))); d != nil {
			crt.Spec.Duration = &metav1.Duration{Duration: time.Duration(*d) * time.Second}
		}
		if alg := hegel.Draw(ht, hegel.Optional(hegel.SampledFrom([]cmapi.PrivateKeyAlgorithm{"RSA", "ECDSA", "Ed25519", "bogus"}))); alg != nil {
			crt.Spec.PrivateKey = &cmapi.CertificatePrivateKey{
				Algorithm: *alg,
				Size:      hegel.Draw(ht, hegel.SampledFrom([]int{-1, 0, 256, 521, 1024, 2048})),
			}
		}

		var secret *corev1.Secret
		if hegel.Draw(ht, hegel.Booleans()) {
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "s",
					Namespace:   "ns",
					Annotations: hegel.Draw(ht, hegel.Maps(annotationKeys, hegel.Text().MaxSize(10)).MaxSize(4)),
				},
				Data: hegel.Draw(ht, hegel.Maps(
					hegel.SampledFrom([]string{"tls.crt", "tls.key", "ca.crt", "junk"}),
					secretValues,
				).MaxSize(4)),
			}
		}

		newCR := func() *cmapi.CertificateRequest {
			return &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "cr",
					Namespace:   "ns",
					Annotations: hegel.Draw(ht, hegel.Maps(annotationKeys, hegel.Text().MaxSize(10)).MaxSize(2)),
				},
				Spec: cmapi.CertificateRequestSpec{
					IssuerRef: crt.Spec.IssuerRef,
					Request:   hegel.Draw(ht, secretValues),
				},
			}
		}
		input := Input{Certificate: crt, Secret: secret}
		if hegel.Draw(ht, hegel.Booleans()) {
			input.CurrentRevisionRequest = newCR()
		}
		if hegel.Draw(ht, hegel.Booleans()) {
			input.NextRevisionRequest = newCR()
		}

		for name, chain := range chains {
			func() {
				defer func() {
					if r := recover(); r != nil {
						ht.Fatalf("%s policy chain panicked: %v (secret=%v, current=%v, next=%v)",
							name, r, secret, input.CurrentRevisionRequest, input.NextRevisionRequest)
					}
				}()
				chain.Evaluate(input)
			}()
		}
	}, hegel.WithTestCases(2000))
}
