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
	"net"
	"reflect"
	"testing"

	"hegel.dev/go/hegel"
)

// TestMarshalUnmarshalSANsRoundTrip checks that any GeneralNames value
// marshalled to a SubjectAltName extension unmarshals back to the same
// value, and that the extension is critical exactly when the certificate
// has no subject. The existing table test pins OpenSSL-generated fixtures
// for interoperability; this property states the general law the table's
// marshal/unmarshal loop spells out per row.
func TestMarshalUnmarshalSANsRoundTrip(t *testing.T) {
	ia5 := hegel.Text().MinSize(1).MaxSize(20).MaxCodepoint(127)
	// A valid OID: first arc 0-2, second arc 0-39, as required by ASN.1 DER.
	oids := hegel.Composite(func(tc hegel.TestCase) asn1.ObjectIdentifier {
		oid := asn1.ObjectIdentifier{
			hegel.Draw(tc, hegel.Integers(0, 2)),
			hegel.Draw(tc, hegel.Integers(0, 39)),
		}
		return append(oid, hegel.Draw(tc, hegel.Lists(hegel.Integers(0, 1<<30)).MaxSize(4))...)
	})
	// OtherName.Value must be the pre-wrapped [0] EXPLICIT element, exactly
	// as buildSANsFromSpec constructs it in csr.go: the asn1 encoder writes
	// RawValues verbatim, so an unwrapped value would marshal to an
	// extension UnmarshalSANs cannot parse.
	otherNames := hegel.Composite(func(tc hegel.TestCase) OtherName {
		inner, err := MarshalUniversalValue(UniversalValue{UTF8String: hegel.Draw(tc, hegel.Text().MinSize(1).MaxSize(20))})
		if err != nil {
			panic(err)
		}
		wrapped, err := asn1.Marshal(asn1.RawValue{Tag: 0, Class: asn1.ClassContextSpecific, IsCompound: true, Bytes: inner})
		if err != nil {
			panic(err)
		}
		var rv asn1.RawValue
		if _, err := asn1.Unmarshal(wrapped, &rv); err != nil {
			panic(err)
		}
		return OtherName{TypeID: hegel.Draw(tc, oids), Value: rv}
	})
	ips := hegel.Map(hegel.Binary(4, 4), func(b []byte) net.IP { return net.IP(b) })

	hegel.Test(t, func(ht *hegel.T) {
		gns := GeneralNames{
			OtherNames:                 hegel.Draw(ht, hegel.Lists(otherNames).MaxSize(2)),
			RFC822Names:                hegel.Draw(ht, hegel.Lists(ia5).MaxSize(2)),
			DNSNames:                   hegel.Draw(ht, hegel.Lists(ia5).MaxSize(3)),
			UniformResourceIdentifiers: hegel.Draw(ht, hegel.Lists(ia5).MaxSize(2)),
			IPAddresses:                hegel.Draw(ht, hegel.Lists(ips).MaxSize(2)),
			RegisteredIDs:              hegel.Draw(ht, hegel.Lists(oids).MaxSize(2)),
		}
		ht.Assume(!gns.Empty())
		hasSubject := hegel.Draw(ht, hegel.Booleans())

		ext, err := MarshalSANs(gns, hasSubject)
		if err != nil {
			ht.Fatalf("failed to marshal %+v: %v", gns, err)
		}
		if ext.Critical != !hasSubject {
			ht.Fatalf("extension critical = %v, want %v (hasSubject=%v)", ext.Critical, !hasSubject, hasSubject)
		}

		back, err := UnmarshalSANs(ext.Value)
		if err != nil {
			ht.Fatalf("failed to unmarshal SANs of %+v: %v", gns, err)
		}
		// Normalize nil vs empty slices before comparing.
		if !reflect.DeepEqual(nonNil(gns), nonNil(back)) {
			ht.Fatalf("round trip changed\n%+v\nto\n%+v", gns, back)
		}
	}, hegel.WithTestCases(2000))
}

// nonNil replaces nil slices with empty ones so DeepEqual compares values,
// not presence.
func nonNil(gns GeneralNames) GeneralNames {
	if gns.OtherNames == nil {
		gns.OtherNames = []OtherName{}
	}
	if gns.RFC822Names == nil {
		gns.RFC822Names = []string{}
	}
	if gns.DNSNames == nil {
		gns.DNSNames = []string{}
	}
	if gns.UniformResourceIdentifiers == nil {
		gns.UniformResourceIdentifiers = []string{}
	}
	if gns.IPAddresses == nil {
		gns.IPAddresses = []net.IP{}
	}
	if gns.RegisteredIDs == nil {
		gns.RegisteredIDs = []asn1.ObjectIdentifier{}
	}
	return gns
}
