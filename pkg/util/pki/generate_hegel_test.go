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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"testing"

	"github.com/cert-manager/cert-manager/internal/pem"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	"hegel.dev/go/hegel"
)

// TestGenerateEncodeDecodePrivateKey checks, for any valid combination of
// private key algorithm, size and encoding, that:
//
//   - GeneratePrivateKeyForCertificate returns a key of the algorithm and
//     size the spec asked for (defaults: RSA 2048, ECDSA P-256)
//   - EncodePrivateKey produces a PEM block of the type implied by the
//     algorithm and encoding (default encoding is PKCS1, except Ed25519
//     which is always PKCS8)
//   - DecodePrivateKeyBytes returns a key with the same public key
//
// RSA sizes above 2048 are excluded only because generating them is slow.
func TestGenerateEncodeDecodePrivateKey(t *testing.T) {
	type spec struct {
		algorithm v1.PrivateKeyAlgorithm
		size      int
	}
	specs := hegel.OneOf(
		hegel.Composite(func(tc hegel.TestCase) spec {
			return spec{v1.RSAKeyAlgorithm, hegel.Draw(tc, hegel.SampledFrom([]int{0, MinRSAKeySize}))}
		}),
		hegel.Composite(func(tc hegel.TestCase) spec {
			return spec{v1.ECDSAKeyAlgorithm, hegel.Draw(tc, hegel.SampledFrom([]int{0, ECCurve256, ECCurve384, ECCurve521}))}
		}),
		hegel.Composite(func(tc hegel.TestCase) spec {
			return spec{v1.Ed25519KeyAlgorithm, hegel.Draw(tc, hegel.Integers(0, 1<<16))}
		}),
		hegel.Composite(func(tc hegel.TestCase) spec {
			return spec{v1.PrivateKeyAlgorithm(""), 0}
		}),
	)

	hegel.Test(t, func(ht *hegel.T) {
		s := hegel.Draw(ht, specs)
		encoding := hegel.Draw(ht, hegel.SampledFrom([]v1.PrivateKeyEncoding{"", v1.PKCS1, v1.PKCS8}))

		key, err := GeneratePrivateKeyForCertificate(buildCertificateWithKeyParams(s.algorithm, s.size))
		if err != nil {
			ht.Fatalf("failed to generate %s/%d key: %v", s.algorithm, s.size, err)
		}

		wantBlockType := "PRIVATE KEY" // PKCS#8
		switch k := key.(type) {
		case *rsa.PrivateKey:
			if s.algorithm != v1.RSAKeyAlgorithm && s.algorithm != "" {
				ht.Fatalf("%s/%d spec produced an RSA key", s.algorithm, s.size)
			}
			wantSize := MinRSAKeySize
			if s.size != 0 {
				wantSize = s.size
			}
			if k.N.BitLen() != wantSize {
				ht.Fatalf("%s/%d spec produced an RSA key of size %d", s.algorithm, s.size, k.N.BitLen())
			}
			if encoding != v1.PKCS8 {
				wantBlockType = "RSA PRIVATE KEY"
			}
		case *ecdsa.PrivateKey:
			if s.algorithm != v1.ECDSAKeyAlgorithm {
				ht.Fatalf("%s/%d spec produced an ECDSA key", s.algorithm, s.size)
			}
			wantCurve, err := ecCurveForKeySize(s.size)
			if err != nil {
				ht.Fatalf("%v", err)
			}
			if k.Curve != wantCurve {
				ht.Fatalf("%s/%d spec produced a key on curve %s", s.algorithm, s.size, k.Curve.Params().Name)
			}
			if encoding != v1.PKCS8 {
				wantBlockType = "EC PRIVATE KEY"
			}
		case ed25519.PrivateKey:
			if s.algorithm != v1.Ed25519KeyAlgorithm {
				ht.Fatalf("%s/%d spec produced an Ed25519 key", s.algorithm, s.size)
			}
		default:
			ht.Fatalf("%s/%d spec produced unexpected key type %T", s.algorithm, s.size, key)
		}

		encoded, err := EncodePrivateKey(key, encoding)
		if err != nil {
			ht.Fatalf("failed to encode %s/%d key as %q: %v", s.algorithm, s.size, encoding, err)
		}
		block, _, err := pem.SafeDecodePrivateKey(encoded)
		if err != nil {
			ht.Fatalf("failed to PEM-decode encoded %s/%d key: %v", s.algorithm, s.size, err)
		}
		if block.Type != wantBlockType {
			ht.Fatalf("%s/%d key encoded as %q has PEM block type %q, want %q", s.algorithm, s.size, encoding, block.Type, wantBlockType)
		}

		decoded, err := DecodePrivateKeyBytes(encoded)
		if err != nil {
			ht.Fatalf("failed to decode encoded %s/%d key: %v", s.algorithm, s.size, err)
		}
		equal, err := PublicKeysEqual(decoded.Public(), key.Public())
		if err != nil {
			ht.Fatalf("failed to compare public keys: %v", err)
		}
		if !equal {
			ht.Fatalf("%s/%d key changed public key after encode/decode round trip", s.algorithm, s.size)
		}
	}, hegel.WithTestCases(30))
}

// TestGeneratePrivateKeyInvalidSpecs checks that out-of-range RSA sizes,
// unsupported ECDSA sizes and unknown algorithms are all rejected.
func TestGeneratePrivateKeyInvalidSpecs(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		var crt *v1.Certificate
		switch hegel.Draw(ht, hegel.Integers(0, 2)) {
		case 0:
			size := hegel.Draw(ht, hegel.OneOf(
				hegel.Integers(1, MinRSAKeySize-1),
				hegel.Integers(MaxRSAKeySize+1, 1<<20),
			))
			crt = buildCertificateWithKeyParams(v1.RSAKeyAlgorithm, size)
		case 1:
			size := hegel.Draw(ht, hegel.Integers(1, 1<<20))
			ht.Assume(size != ECCurve256 && size != ECCurve384 && size != ECCurve521)
			crt = buildCertificateWithKeyParams(v1.ECDSAKeyAlgorithm, size)
		case 2:
			algorithm := hegel.Draw(ht, hegel.Text().MinSize(1).MaxSize(10))
			ht.Assume(algorithm != string(v1.RSAKeyAlgorithm) &&
				algorithm != string(v1.ECDSAKeyAlgorithm) &&
				algorithm != string(v1.Ed25519KeyAlgorithm))
			crt = buildCertificateWithKeyParams(v1.PrivateKeyAlgorithm(algorithm), 256)
		}

		if key, err := GeneratePrivateKeyForCertificate(crt); err == nil {
			ht.Fatalf("expected error for %+v, got key %T", crt.Spec.PrivateKey, key)
		}
	})
}
