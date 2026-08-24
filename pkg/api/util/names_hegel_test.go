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

package util

import (
	"testing"

	"hegel.dev/go/hegel"
)

func isASCIIAlnum(b byte) bool {
	return 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9'
}

// TestDNSSafeShortenToNCharactersProperties checks DNSSafeShortenToNCharacters
// against a recomputed oracle: for inputs of at least maxLength bytes the
// result is the longest prefix of in[:maxLength] that ends in an ASCII
// alphanumeric byte, or "" if there is none.
//
// Note the documented guarantee that "the last char is an alpha-numeric
// character" only holds for such inputs: an input shorter than maxLength is
// returned unchanged, even if it ends in a non-alphanumeric character. In
// practice inputs are Kubernetes resource names, which must end in an
// alphanumeric, so the second branch's weaker behavior is harmless.
func TestDNSSafeShortenToNCharactersProperties(t *testing.T) {
	inputs := hegel.Text().MaxSize(30).Alphabet("aB9-._*é")

	hegel.Test(t, func(ht *hegel.T) {
		in := hegel.Draw(ht, inputs)
		maxLength := hegel.Draw(ht, hegel.Integers(0, 40))

		out := DNSSafeShortenToNCharacters(in, maxLength)

		if len(in) < maxLength {
			if out != in {
				ht.Fatalf("shorten(%q, %d): got %q, want input unchanged", in, maxLength, out)
			}
			return
		}

		want := ""
		for i := range maxLength {
			if isASCIIAlnum(in[i]) {
				want = in[:i+1]
			}
		}
		if out != want {
			ht.Fatalf("shorten(%q, %d): got %q, want %q", in, maxLength, out, want)
		}
	})
}
