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
	"net"
	"reflect"
	"testing"

	"hegel.dev/go/hegel"
)

// TestMarshalUnmarshalNameConstraintsRoundTrip checks that any NameConstraints
// value marshalled to an extension unmarshals back to the same value, with
// the requested criticality. The existing table test pins OpenSSL-generated
// fixtures for interoperability; this property states the law its rows
// spell out per fixture.
func TestMarshalUnmarshalNameConstraintsRoundTrip(t *testing.T) {
	ia5 := hegel.Text().MinSize(1).MaxSize(20).MaxCodepoint(127)
	ia5List := hegel.Lists(ia5).MaxSize(2)
	// Generate CIDR-masked networks; MarshalNameConstraints masks the IP
	// itself, so pre-masked inputs are the values that can round-trip.
	ipNets := hegel.Composite(func(tc hegel.TestCase) *net.IPNet {
		size := 4
		if hegel.Draw(tc, hegel.Booleans()) {
			size = 16
		}
		mask := net.CIDRMask(hegel.Draw(tc, hegel.Integers(0, size*8)), size*8)
		ip := net.IP(hegel.Draw(tc, hegel.Binary(size, size))).Mask(mask)
		return &net.IPNet{IP: ip, Mask: mask}
	})
	ipNetList := hegel.Lists(ipNets).MaxSize(2)

	hegel.Test(t, func(ht *hegel.T) {
		nc := &NameConstraints{
			PermittedDNSDomains:     hegel.Draw(ht, ia5List),
			ExcludedDNSDomains:      hegel.Draw(ht, ia5List),
			PermittedIPRanges:       hegel.Draw(ht, ipNetList),
			ExcludedIPRanges:        hegel.Draw(ht, ipNetList),
			PermittedEmailAddresses: hegel.Draw(ht, ia5List),
			ExcludedEmailAddresses:  hegel.Draw(ht, ia5List),
			PermittedURIDomains:     hegel.Draw(ht, ia5List),
			ExcludedURIDomains:      hegel.Draw(ht, ia5List),
		}
		ht.Assume(!nc.IsEmpty())
		critical := hegel.Draw(ht, hegel.Booleans())

		ext, err := MarshalNameConstraints(nc, critical)
		if err != nil {
			ht.Fatalf("failed to marshal %+v: %v", nc, err)
		}
		if ext.Critical != critical {
			ht.Fatalf("extension critical = %v, want %v", ext.Critical, critical)
		}

		back, err := UnmarshalNameConstraints(ext.Value)
		if err != nil {
			ht.Fatalf("failed to unmarshal constraints of %+v: %v", nc, err)
		}
		if !reflect.DeepEqual(nc, back) {
			ht.Fatalf("round trip changed\n%+v\nto\n%+v", nc, back)
		}
	}, hegel.WithTestCases(2000))
}
