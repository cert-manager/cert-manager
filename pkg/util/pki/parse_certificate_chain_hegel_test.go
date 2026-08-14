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
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"hegel.dev/go/hegel"
)

// drawShuffle returns a drawn permutation of xs, so that failing orderings
// shrink like any other drawn value.
func drawShuffle[T any](ht *hegel.T, xs []T) []T {
	out := append([]T(nil), xs...)
	for i := len(out) - 1; i > 0; i-- {
		j := hegel.Draw(ht, hegel.Integers(0, i))
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// TestEncodeX509ChainProperties checks EncodeX509Chain against its
// recomputable rule: the output is the concatenated PEM encoding of the
// input certificates in order, skipping nils and self-signed certificates.
// The pool includes a certificate whose subject equals its issuer's subject
// (but which is not self-signed), the case from issue #4142.
func TestEncodeX509ChainProperties(t *testing.T) {
	root := mustCreateBundle(t, nil, "root")
	root2 := mustCreateBundle(t, nil, "root2")
	int1 := mustCreateBundle(t, root, "int1")
	int2 := mustCreateBundle(t, int1, "int2")
	leaf := mustCreateBundle(t, int2, "leaf")
	sameCN := mustCreateBundle(t, int1, int1.cert.Subject.CommonName)
	pool := []*testBundle{nil, root, root2, int1, int2, leaf, sameCN}

	hegel.Test(t, func(ht *hegel.T) {
		picks := hegel.Draw(ht, hegel.Lists(hegel.SampledFrom(pool)).MaxSize(6))

		var certs []*x509.Certificate
		var want []byte
		for _, b := range picks {
			if b == nil {
				certs = append(certs, nil)
				continue
			}
			certs = append(certs, b.cert)
			if b.cert.CheckSignatureFrom(b.cert) != nil {
				want = append(want, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.cert.Raw})...)
			}
		}

		got, err := EncodeX509Chain(certs)
		if err != nil {
			ht.Fatalf("failed to encode chain: %v", err)
		}
		if !bytes.Equal(got, want) {
			ht.Fatalf("encoded chain mismatch:\ngot:\n%s\nwant:\n%s", got, want)
		}
	}, hegel.WithTestCases(500))
}

// TestParseSingleCertificateChainProperties checks that for any chain of
// depth 0-3 intermediates, with or without its self-signed root included,
// with any duplicates, in any input order, ParseSingleCertificateChainPEM
// returns the chain in leaf-to-top order with the correct CA:
//
//   - root included: chain excludes the root, CA is the root
//   - root absent, >= 1 intermediate: chain includes the top intermediate,
//     which is also the CA
//   - root absent, single certificate: chain is that certificate, no CA
//
// It also checks that a chain with a gap, or with an unrelated self-signed
// certificate added, is rejected. Certificates are drawn from a pool that
// includes leaves whose CN equals their issuer's CN (issue #4142).
func TestParseSingleCertificateChainProperties(t *testing.T) {
	root := mustCreateBundle(t, nil, "root")
	foreign := mustCreateBundle(t, nil, "foreign")
	ints := []*testBundle{}
	parent := root
	for range 3 {
		parent = mustCreateBundle(t, parent, "int")
		ints = append(ints, parent)
	}
	// leaves[n] is signed by ints[n-1] (by root for n==0); one ordinary, one
	// with the same CN as its issuer.
	leaves := make([][2]*testBundle, 4)
	for n := range 4 {
		issuer := root
		if n > 0 {
			issuer = ints[n-1]
		}
		leaves[n] = [2]*testBundle{
			mustCreateBundle(t, issuer, "leaf"),
			mustCreateBundle(t, issuer, issuer.cert.Subject.CommonName),
		}
	}

	hegel.Test(t, func(ht *hegel.T) {
		n := hegel.Draw(ht, hegel.Integers(0, 3))
		includeRoot := hegel.Draw(ht, hegel.Booleans())
		leaf := leaves[n][0]
		if hegel.Draw(ht, hegel.Booleans()) {
			leaf = leaves[n][1]
		}

		// ordered, top first
		ordered := []*testBundle{}
		if includeRoot {
			ordered = append(ordered, root)
		}
		ordered = append(ordered, ints[:n]...)
		ordered = append(ordered, leaf)

		var wantChain, wantCA []byte
		for i := len(ordered) - 1; i >= 0; i-- {
			if ordered[i] != root {
				wantChain = append(wantChain, ordered[i].pem...)
			}
		}
		switch {
		case includeRoot:
			wantCA = root.pem
		case n > 0:
			wantCA = ints[0].pem
		}

		input := ordered
		for range hegel.Draw(ht, hegel.Integers(0, 2)) {
			input = append(input, input[hegel.Draw(ht, hegel.Integers(0, len(input)-1))])
		}
		input = drawShuffle(ht, input)

		var inputPEM []byte
		for _, b := range input {
			inputPEM = append(inputPEM, b.pem...)
		}
		bundle, err := ParseSingleCertificateChainPEM(inputPEM)
		if err != nil {
			ht.Fatalf("failed to parse (n=%d, includeRoot=%v): %v", n, includeRoot, err)
		}
		if !bytes.Equal(bundle.ChainPEM, wantChain) || !bytes.Equal(bundle.CAPEM, wantCA) {
			ht.Fatalf("wrong bundle (n=%d, includeRoot=%v):\ngot chain:\n%s\nwant chain:\n%s\ngot CA:\n%s\nwant CA:\n%s",
				n, includeRoot, bundle.ChainPEM, wantChain, bundle.CAPEM, wantCA)
		}
	}, hegel.WithTestCases(500))

	hegel.Test(t, func(ht *hegel.T) {
		// A full chain root -> ints -> leaf, broken by removing an
		// intermediate or polluted with an unrelated self-signed certificate.
		input := []*testBundle{root, ints[0], ints[1], ints[2], leaves[3][0]}
		if hegel.Draw(ht, hegel.Booleans()) {
			gap := hegel.Draw(ht, hegel.Integers(1, 3))
			input = append(input[:gap:gap], input[gap+1:]...)
		} else {
			input = append(input, foreign)
		}
		input = drawShuffle(ht, input)

		var inputPEM []byte
		for _, b := range input {
			inputPEM = append(inputPEM, b.pem...)
		}
		if bundle, err := ParseSingleCertificateChainPEM(inputPEM); err == nil {
			ht.Fatalf("expected broken-chain error, got bundle:\n%s", bundle.ChainPEM)
		}
	}, hegel.WithTestCases(200))
}
