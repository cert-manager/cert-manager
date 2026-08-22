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

package pki

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	"hegel.dev/go/hegel"
)

// TestSignatureAlgorithmMatchesGeneratedKey checks the end-to-end contract of
// SignatureAlgorithm: for any valid spec (with signatureAlgorithm either
// unset or one the webhook allows for the key algorithm, per
// keyAlgToAllowedSigAlgs in internal/apis/certmanager/validation), the
// predicted algorithms must be usable with the key that
// GeneratePrivateKeyForCertificate generates for the same spec: a CSR created
// with them parses back with exactly the predicted public key and signature
// algorithms. The existing table test pins which default digest each key size
// gets; this property verifies the predictions actually work.
func TestSignatureAlgorithmMatchesGeneratedKey(t *testing.T) {
	type spec struct {
		algorithm v1.PrivateKeyAlgorithm
		size      int
		sigAlgs   []v1.SignatureAlgorithm
	}
	// RSA sizes above 2048 are excluded only because generating them is slow.
	specs := hegel.OneOf(
		hegel.Composite(func(tc hegel.TestCase) spec {
			return spec{
				algorithm: hegel.Draw(tc, hegel.SampledFrom([]v1.PrivateKeyAlgorithm{"", v1.RSAKeyAlgorithm})),
				size:      hegel.Draw(tc, hegel.SampledFrom([]int{0, MinRSAKeySize})),
				sigAlgs:   []v1.SignatureAlgorithm{v1.SHA256WithRSA, v1.SHA384WithRSA, v1.SHA512WithRSA},
			}
		}),
		hegel.Composite(func(tc hegel.TestCase) spec {
			return spec{
				algorithm: v1.ECDSAKeyAlgorithm,
				size:      hegel.Draw(tc, hegel.SampledFrom([]int{0, ECCurve256, ECCurve384, ECCurve521})),
				sigAlgs:   []v1.SignatureAlgorithm{v1.ECDSAWithSHA256, v1.ECDSAWithSHA384, v1.ECDSAWithSHA512},
			}
		}),
		hegel.Composite(func(tc hegel.TestCase) spec {
			return spec{
				algorithm: v1.Ed25519KeyAlgorithm,
				sigAlgs:   []v1.SignatureAlgorithm{v1.PureEd25519},
			}
		}),
	)

	hegel.Test(t, func(ht *hegel.T) {
		s := hegel.Draw(ht, specs)
		var sigAlg v1.SignatureAlgorithm
		if hegel.Draw(ht, hegel.Booleans()) {
			sigAlg = hegel.Draw(ht, hegel.SampledFrom(s.sigAlgs))
		}
		crt := buildCertificateWithKeyAndSigParams(s.algorithm, s.size, sigAlg)

		wantPub, wantSig, err := SignatureAlgorithm(crt)
		if err != nil {
			ht.Fatalf("SignatureAlgorithm failed for %s/%d/%s: %v", s.algorithm, s.size, sigAlg, err)
		}

		key, err := GeneratePrivateKeyForCertificate(crt)
		if err != nil {
			ht.Fatalf("failed to generate key for %s/%d: %v", s.algorithm, s.size, err)
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			SignatureAlgorithm: wantSig,
			Subject:            pkix.Name{CommonName: "test"},
		}, key)
		if err != nil {
			ht.Fatalf("predicted %v/%v unusable with generated %s/%d key: %v", wantPub, wantSig, s.algorithm, s.size, err)
		}
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			ht.Fatalf("failed to parse CSR: %v", err)
		}
		if csr.PublicKeyAlgorithm != wantPub || csr.SignatureAlgorithm != wantSig {
			ht.Fatalf("CSR has %v/%v, predicted %v/%v (spec %s/%d/%s)",
				csr.PublicKeyAlgorithm, csr.SignatureAlgorithm, wantPub, wantSig, s.algorithm, s.size, sigAlg)
		}
	}, hegel.WithTestCases(30))
}
