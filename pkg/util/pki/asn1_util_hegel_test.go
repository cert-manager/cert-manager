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
	"encoding/asn1"
	"math"
	"reflect"
	"strings"
	"testing"

	"hegel.dev/go/hegel"
)

// TestParseObjectIdentifierRoundTrip checks that any OID formatted with the
// standard library's asn1.ObjectIdentifier.String parses back to the same
// OID, and that a string with any non-numeric component is rejected.
func TestParseObjectIdentifierRoundTrip(t *testing.T) {
	components := hegel.Lists(hegel.Integers(0, math.MaxInt32)).MinSize(1).MaxSize(8)

	hegel.Test(t, func(ht *hegel.T) {
		oid := asn1.ObjectIdentifier(hegel.Draw(ht, components))
		parsed, err := ParseObjectIdentifier(oid.String())
		if err != nil {
			ht.Fatalf("failed to parse %q: %v", oid.String(), err)
		}
		if !parsed.Equal(oid) {
			ht.Fatalf("parsed %q to %v, want %v", oid.String(), parsed, oid)
		}
	})

	hegel.Test(t, func(ht *hegel.T) {
		parts := make([]string, 0, 4)
		for _, c := range hegel.Draw(ht, components.MaxSize(3)) {
			parts = append(parts, asn1.ObjectIdentifier{c}.String())
		}
		bad := hegel.Draw(ht, hegel.SampledFrom([]string{"", "x", "5x", " 5"}))
		at := hegel.Draw(ht, hegel.Integers(0, len(parts)))
		s := strings.Join(append(parts[:at:at], append([]string{bad}, parts[at:]...)...), ".")

		if oid, err := ParseObjectIdentifier(s); err == nil {
			ht.Fatalf("expected error parsing %q with non-numeric component %q, got %v", s, bad, oid)
		}
	})
}

// TestUniversalValueRoundTrip checks, for each string form of UniversalValue,
// that MarshalUniversalValue produces exactly the standard library's encoding
// of the corresponding tagged string, and that unmarshalling returns the
// original value. It also checks the normalization law the old table encoded
// as a special case: a Bytes-form UniversalValue holding the encoding of a
// tagged string unmarshals to the string form, not the Bytes form.
//
// Empty strings are not representable: UniversalValue treats a "" field as
// unset, so generated values have at least one character.
func TestUniversalValueRoundTrip(t *testing.T) {
	printableAlphabet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'()+,-./ :=?*&"
	forms := []struct {
		name string
		gen  hegel.Generator[string]
		make func(s string) UniversalValue
		tag  int
	}{
		{
			name: "IA5String",
			gen:  hegel.Text().MinSize(1).MaxSize(20).MaxCodepoint(127),
			make: func(s string) UniversalValue { return UniversalValue{IA5String: s} },
			tag:  asn1.TagIA5String,
		},
		{
			name: "UTF8String",
			gen:  hegel.Text().MinSize(1).MaxSize(20),
			make: func(s string) UniversalValue { return UniversalValue{UTF8String: s} },
			tag:  asn1.TagUTF8String,
		},
		{
			name: "PrintableString",
			gen:  hegel.Text().MinSize(1).MaxSize(20).Alphabet(printableAlphabet),
			make: func(s string) UniversalValue { return UniversalValue{PrintableString: s} },
			tag:  asn1.TagPrintableString,
		},
	}

	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			hegel.Test(t, func(ht *hegel.T) {
				s := hegel.Draw(ht, form.gen)
				uv := form.make(s)

				marshaled, err := MarshalUniversalValue(uv)
				if err != nil {
					ht.Fatalf("failed to marshal %q: %v", s, err)
				}

				want, err := asn1.Marshal(asn1.RawValue{
					Class: asn1.ClassUniversal,
					Tag:   form.tag,
					Bytes: []byte(s),
				})
				if err != nil {
					ht.Fatalf("stdlib failed to marshal %q: %v", s, err)
				}
				if !reflect.DeepEqual(marshaled, want) {
					ht.Fatalf("marshal of %q: got %x, want %x", s, marshaled, want)
				}

				back, err := UnmarshalUniversalValue(asn1.RawValue{
					Class: asn1.ClassUniversal,
					Tag:   form.tag,
					Bytes: []byte(s),
				})
				if err != nil {
					ht.Fatalf("failed to unmarshal %x: %v", marshaled, err)
				}
				if !reflect.DeepEqual(back, uv) {
					ht.Fatalf("round trip of %q: got %+v, want %+v", s, back, uv)
				}

				// Normalization: the same encoding presented as raw Bytes
				// unmarshals to the string form.
				var raw asn1.RawValue
				if _, err := asn1.Unmarshal(marshaled, &raw); err != nil {
					ht.Fatalf("failed to reparse %x: %v", marshaled, err)
				}
				normalized, err := UnmarshalUniversalValue(raw)
				if err != nil {
					ht.Fatalf("failed to unmarshal reparsed %x: %v", marshaled, err)
				}
				if !reflect.DeepEqual(normalized, uv) {
					ht.Fatalf("normalization of %q: got %+v, want %+v", s, normalized, uv)
				}
			})
		})
	}
}
