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

package util

import (
	"net"
	"net/url"
	"slices"
	"testing"
)

type testT struct {
	desc  string
	s1    []string
	s2    []string
	equal bool
}

var stringSliceTestData = []testT{
	{
		desc:  "equal but out of order slices should be equal",
		s1:    []string{"a", "b", "c"},
		s2:    []string{"b", "a", "c"},
		equal: true,
	},
	{
		desc:  "non-equal but ordered slices should not be equal",
		s1:    []string{"a", "b"},
		s2:    []string{"a", "b", "c"},
		equal: false,
	},
	{
		desc:  "non-equal but ordered slices should not be equal",
		s1:    []string{"a", "b", "c"},
		s2:    []string{"a", "b"},
		equal: false,
	},
	{
		desc:  "equal and ordered slices should be equal",
		s1:    []string{"a", "b", "c"},
		s2:    []string{"a", "b", "c"},
		equal: true,
	},
	{
		desc:  "unequal lists of the same length are not equal",
		s1:    []string{"example.com"},
		s2:    []string{"notexample.com"},
		equal: false,
	},
}

func TestEqualUnsorted(t *testing.T) {
	for _, test := range stringSliceTestData {
		t.Run(test.desc, func(test testT) func(*testing.T) {
			return func(t *testing.T) {
				if actual := EqualUnsorted(test.s1, test.s2); actual != test.equal {
					t.Errorf("equalUnsorted(%+v, %+v) = %t, but expected %t", test.s1, test.s2, actual, test.equal)
				}
			}
		}(test))
	}
}

func TestEqualURLsUnsorted(t *testing.T) {
	for _, test := range stringSliceTestData {
		s1, s2 := parseURLs(t, test.s1), parseURLs(t, test.s2)
		t.Run(test.desc, func(test testT) func(*testing.T) {
			return func(t *testing.T) {
				if actual := EqualURLsUnsorted(s1, s2); actual != test.equal {
					t.Errorf("equalURLsUnsorted(%+v, %+v) = %t, but expected %t", s1, s2, actual, test.equal)
				}
			}
		}(test))
	}
}

func TestEqualIPsUnsorted(t *testing.T) {
	// This test uses string representations of IP addresses because it's much more convenient to
	// represent different types of IPv6 address as strings. This implicitly relies on the behavior
	// of net.ParseIP under the hood when it comes to parsing IPv4 addresses, though - it could return
	// either a 4 or 16 byte slice to represent an IPv4 address. As such, we have a separate test
	// which uses raw net.IP byte slices below, which checks that we're not relying on underlying
	// behavior of ParseIP when comparing.
	specs := map[string]struct {
		s1 []string
		s2 []string

		expEqual bool
	}{
		"simple ipv4 comparison": {
			s1:       []string{"8.8.8.8", "1.1.1.1"},
			s2:       []string{"1.1.1.1", "8.8.8.8"},
			expEqual: true,
		},
		"simple ipv6 comparison": {
			s1:       []string{"2a00:1450:4009:822::200e", "2a03:2880:f166:81:face:b00c:0:25de"},
			s2:       []string{"2a03:2880:f166:81:face:b00c:0:25de", "2a00:1450:4009:822::200e"},
			expEqual: true,
		},
		"mixed ipv4 and ipv6": {
			s1:       []string{"2a00:1450:4009:822::200e", "2a03:2880:f166:81:face:b00c:0:25de", "1.1.1.1"},
			s2:       []string{"2a03:2880:f166:81:face:b00c:0:25de", "1.1.1.1", "2a00:1450:4009:822::200e"},
			expEqual: true,
		},
		"mixed ipv6 specificity": {
			s1:       []string{"2a03:2880:f166:0081:face:b00c:0000:25de"},
			s2:       []string{"2a03:2880:f166:81:face:b00c:0:25de"},
			expEqual: true,
		},
		"unequal addresses ipv6": {
			s1:       []string{"2a03:2880:f166:0081:face::25de"},
			s2:       []string{"2a03:2880:f166:81:face:b00c:1:25de"},
			expEqual: false,
		},
	}

	for name, spec := range specs {
		s1 := parseIPs(spec.s1)
		s2 := parseIPs(spec.s2)

		t.Run(name, func(t *testing.T) {
			got := EqualIPsUnsorted(s1, s2)

			if got != spec.expEqual {
				t.Errorf("EqualIPsUnsorted(%+v, %+v) = %t, but expected %t", s1, s2, got, spec.expEqual)
			}
		})
	}
}

func TestEqualIPsUnsorted_RawIPs(t *testing.T) {
	// See description in  TestEqualIPsUnsorted for motivation here
	specs := map[string]struct {
		s1 []net.IP
		s2 []net.IP

		expEqual bool
	}{
		"simple ipv4 comparison": {
			s1:       []net.IP{net.IP([]byte{0x1, 0x1, 0x1, 0x1}), net.IP([]byte{0x8, 0x8, 0x8, 0x8})},
			s2:       []net.IP{net.IP([]byte{0x8, 0x8, 0x8, 0x8}), net.IP([]byte{0x1, 0x1, 0x1, 0x1})},
			expEqual: true,
		},
		"simple ipv6 comparison": {
			s1: []net.IP{
				net.IP([]byte{0x2a, 0xe, 0x23, 0x45, 0x67, 0x89, 0x0, 0x1, 0x0, 0x1, 0x0, 0x2, 0x0, 0x0, 0x0, 0x6}),
				net.IP([]byte{0x2a, 0x03, 0x28, 0x80, 0xf1, 0x66, 0x00, 0x81, 0xfa, 0xce, 0xb0, 0x0c, 0x00, 0x00, 0x25, 0xde}),
			},
			s2: []net.IP{
				net.IP([]byte{0x2a, 0x03, 0x28, 0x80, 0xf1, 0x66, 0x00, 0x81, 0xfa, 0xce, 0xb0, 0x0c, 0x00, 0x00, 0x25, 0xde}),
				net.IP([]byte{0x2a, 0xe, 0x23, 0x45, 0x67, 0x89, 0x0, 0x1, 0x0, 0x1, 0x0, 0x2, 0x0, 0x0, 0x0, 0x6}),
			},
			expEqual: true,
		},
		"mixed ipv4 lengths": {
			// This is the most important test in this test function!
			// IPv4 addresses have two valid representations as `net.IP`s and we shouldn't miss the case where they're equal
			s1: []net.IP{
				net.IP([]byte{0xa, 0x0, 0x0, 0xce}),
			},
			s2: []net.IP{
				net.IP([]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xa, 0x0, 0x0, 0xce}),
			},
			expEqual: true,
		},
	}

	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			got := EqualIPsUnsorted(spec.s1, spec.s2)

			if got != spec.expEqual {
				t.Errorf("EqualIPsUnsorted(%+v, %+v) = %t, but expected %t", spec.s1, spec.s2, got, spec.expEqual)
			}
		})
	}
}

func TestContains(t *testing.T) {
	type testT struct {
		desc  string
		slice []string
		value string
		equal bool
	}
	tests := []testT{
		{
			desc:  "slice containing value",
			slice: []string{"a", "b", "c"},
			value: "a",
			equal: true,
		},
		{
			desc:  "slice not containing value",
			slice: []string{"a", "b", "c"},
			value: "x",
			equal: false,
		},
		{
			desc:  "empty slice",
			slice: []string{},
			value: "x",
			equal: false,
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(test testT) func(*testing.T) {
			return func(t *testing.T) {
				if actual := slices.Contains(test.slice, test.value); actual != test.equal {
					t.Errorf("Contains(%+v, %+v) = %t, but expected %t", test.slice, test.value, actual, test.equal)
				}
			}
		}(test))
	}
}

func parseURLs(t *testing.T, urlStrs []string) []*url.URL {
	var urls []*url.URL

	for _, u := range urlStrs {
		url, err := url.Parse(u)
		if err != nil {
			t.Errorf("failed to parse url %s: %s", u, err)
			t.FailNow()
		}

		urls = append(urls, url)
	}

	return urls
}

func parseIPs(ipStrs []string) []net.IP {
	var ips []net.IP

	for _, i := range ipStrs {
		ips = append(ips, net.ParseIP(i))
	}

	return ips
}
