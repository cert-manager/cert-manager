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
	"reflect"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"hegel.dev/go/hegel"
)

// TestUnmarshalSubjectStringRoundTrip checks two properties of the
// LiteralSubject parsing pipeline for arbitrary attribute values:
//
//  1. A subject string built from DN-escaped values parses back to an
//     RDNSequence containing exactly those values, in reverse order.
//  2. The parsed RDNSequence survives a DER marshal/unmarshal round-trip
//     unchanged (the same pipeline used to build CSRs and to match
//     certificates against their spec).
func TestUnmarshalSubjectStringRoundTrip(t *testing.T) {
	attrNames := make([]string, 0, len(attributeTypeNames))
	for name := range attributeTypeNames {
		attrNames = append(attrNames, name)
	}

	type atv struct{ Type, Value string }

	hegel.Test(t, func(ht *hegel.T) {
		atvs := hegel.Draw(ht, hegel.Lists(hegel.Composite(func(tc hegel.TestCase) atv {
			return atv{
				Type:  hegel.Draw(tc, hegel.SampledFrom(attrNames)),
				Value: hegel.Draw(tc, hegel.Text().MinSize(1)),
			}
		})).MinSize(1).MaxSize(5))

		parts := make([]string, 0, len(atvs))
		for _, a := range atvs {
			parts = append(parts, a.Type+"="+ldap.EscapeDN(a.Value))
		}
		subject := strings.Join(parts, ",")

		rdns, err := UnmarshalSubjectStringToRDNSequence(subject)
		if err != nil {
			ht.Fatalf("failed to parse subject string %q: %v", subject, err)
		}

		if len(rdns) != len(atvs) {
			ht.Fatalf("subject %q: got %d RDNs, want %d", subject, len(rdns), len(atvs))
		}
		// RDNs in string form are written in reverse order of the sequence.
		for i, a := range atvs {
			got := rdns[len(rdns)-1-i]
			if len(got) != 1 {
				ht.Fatalf("subject %q: RDN %d has %d attributes, want 1", subject, i, len(got))
			}
			if !got[0].Type.Equal(asn1.ObjectIdentifier(attributeTypeNames[a.Type])) {
				ht.Fatalf("subject %q: RDN %d has type %v, want %s", subject, i, got[0].Type, a.Type)
			}
			if got[0].Value != a.Value {
				ht.Fatalf("subject %q: RDN %d has value %q, want %q", subject, i, got[0].Value, a.Value)
			}
		}

		der, err := MarshalRDNSequenceToRawDERBytes(rdns)
		if err != nil {
			ht.Fatalf("failed to marshal %v to DER: %v", rdns, err)
		}
		back, err := UnmarshalRawDerBytesToRDNSequence(der)
		if err != nil {
			ht.Fatalf("failed to unmarshal DER of %v: %v", rdns, err)
		}
		if !reflect.DeepEqual(rdns, back) {
			ht.Fatalf("DER round-trip changed the RDNSequence: %v != %v", rdns, back)
		}
	}, hegel.WithTestCases(5000))
}
